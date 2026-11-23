use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, CNAME, NS};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use hickory_proto::serialize::binary::{BinEncoder, Restrict};
use tokio::sync::{Notify, Semaphore, mpsc};
use tokio::time::sleep_until;

use crate::cache::{self, Cache, Entry, StoredRecord};
use crate::config::Config;
use crate::geo::{self, Country};
use crate::lists::{self, Lists, in_iran, is_cloudflare};
use crate::poison::is_poison_v4;
use crate::probe;
use crate::rank::{rank_key, select_addresses};
use crate::recurse::Recursors;
use crate::siblings;
use crate::upstream::{self, QueryResult};

const MAX_ADDITIONAL_RECORDS: usize = 8;
const AUTH_NS_CAP: usize = 8;

struct Flight {
    done: AtomicBool,
    notify: Notify,
}

enum Observation {
    Recursor(Message),
    Answered(IpAddr, Message),
    Names(Message),
    Failed(IpAddr),
    RecursionMiss,
    Sibling(Message),
    Geo(Message),
}

pub struct Engine {
    config: Config,
    cache: Cache,
    lists: std::sync::RwLock<Lists>,
    inflight: Mutex<std::collections::HashMap<(String, u16), Arc<Flight>>>,
    probes: Arc<Semaphore>,
    discover: Arc<Semaphore>,
    recursors: Arc<Recursors>,
    http: reqwest::Client,
    geos: std::sync::RwLock<Vec<Country>>,
    geo_slots: Arc<Semaphore>,
}

pub struct Answer {
    pub answers: Vec<Record>,
    pub additionals: Vec<Record>,
    pub nxdomain: bool,
}

impl Engine {
    pub fn open(config: Config) -> Arc<Self> {
        let _ = std::fs::create_dir_all(&config.data_dir);
        let cache = Cache::open(&config.data_dir.join("cache.sqlite")).expect("open cache");
        let lists = lists::load_snapshot(&config.data_dir);
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("opinionated-dns")
            .build()
            .expect("http client");
        let geos = geo::load_snapshot(&config.data_dir);
        let engine = Arc::new(Self {
            config,
            cache,
            lists: std::sync::RwLock::new(lists),
            inflight: Mutex::new(std::collections::HashMap::new()),
            probes: Arc::new(Semaphore::new(32)),
            discover: Arc::new(Semaphore::new(256)),
            recursors: Arc::new(Recursors::open()),
            http,
            geos: std::sync::RwLock::new(geos),
            geo_slots: Arc::new(Semaphore::new(16)),
        });
        let refresh = Arc::clone(&engine);
        tokio::spawn(async move { refresh.list_loop().await });
        let geos = Arc::clone(&engine);
        tokio::spawn(async move { geos.geo_loop().await });
        engine
    }

    pub async fn resolve(self: &Arc<Self>, name: Name, qtype: RecordType) -> Answer {
        let qname = normalize(&name);
        let now = cache::now_secs();
        if let Some(entry) = self.cache.get(&qname, u16::from(qtype)) {
            if cache::answers_immediately(Some(&entry)) && !entry.answers.is_empty() {
                if now >= entry.retry_not_before {
                    self.spawn_refresh(name.clone(), qtype);
                }
                return self.entry_to_answer(&name, qtype, &entry);
            }
            if entry.negative && now < entry.retry_not_before {
                return Answer {
                    answers: Vec::new(),
                    additionals: Vec::new(),
                    nxdomain: false,
                };
            }
        }
        let flight = self.spawn_refresh(name.clone(), qtype);
        let notified = flight.notify.notified();
        tokio::pin!(notified);
        if !flight.done.load(Ordering::Acquire) {
            let _ = tokio::time::timeout(self.config.cold_wait(), &mut notified).await;
        }
        if let Some(entry) = self.cache.get(&qname, u16::from(qtype)) {
            if !entry.answers.is_empty() {
                return self.entry_to_answer(&name, qtype, &entry);
            }
            if entry.negative {
                return Answer {
                    answers: Vec::new(),
                    additionals: Vec::new(),
                    nxdomain: false,
                };
            }
        }
        Answer {
            answers: Vec::new(),
            additionals: Vec::new(),
            nxdomain: false,
        }
    }

    fn spawn_refresh(self: &Arc<Self>, name: Name, qtype: RecordType) -> Arc<Flight> {
        let key = (normalize(&name), u16::from(qtype));
        let mut inflight = self.inflight.lock().expect("inflight");
        if let Some(existing) = inflight.get(&key) {
            return Arc::clone(existing);
        }
        let flight = Arc::new(Flight {
            done: AtomicBool::new(false),
            notify: Notify::new(),
        });
        inflight.insert(key.clone(), Arc::clone(&flight));
        drop(inflight);
        let engine = Arc::clone(self);
        let done = Arc::clone(&flight);
        tokio::spawn(async move {
            engine.refresh(name, qtype).await;
            done.done.store(true, Ordering::Release);
            done.notify.notify_waiters();
            engine.inflight.lock().expect("inflight").remove(&key);
        });
        flight
    }

    async fn refresh(self: &Arc<Self>, name: Name, qtype: RecordType) {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut initial = 0usize;
        let recursion_limit = Duration::from_millis(self.config.recursion_timeout_ms);
        let iranian_limit = Duration::from_millis(self.config.iranian_timeout_ms);
        let discovered_limit = Duration::from_millis(800);
        spawn_recursion(
            &tx,
            &mut initial,
            Arc::clone(&self.recursors),
            name.clone(),
            qtype,
            recursion_limit,
            false,
        );
        if matches!(
            qtype,
            RecordType::A
                | RecordType::AAAA
                | RecordType::CNAME
                | RecordType::HTTPS
                | RecordType::SVCB
        ) {
            spawn_recursion(
                &tx,
                &mut initial,
                Arc::clone(&self.recursors),
                name.clone(),
                RecordType::NS,
                recursion_limit,
                true,
            );
        }
        let discovered = self.lists.read().expect("lists").discovered.clone();
        for server in discovered {
            if self.cache.resolver_down(server.ip()) {
                continue;
            }
            spawn_query(
                &tx,
                &mut initial,
                server,
                name.clone(),
                qtype,
                true,
                discovered_limit,
                false,
                false,
                Some(Arc::clone(&self.discover)),
            );
        }
        let resolvers = self.lists.read().expect("lists").resolvers.clone();
        for resolver in resolvers {
            if self.cache.resolver_down(resolver.ip()) {
                continue;
            }
            spawn_query(
                &tx,
                &mut initial,
                resolver,
                name.clone(),
                qtype,
                true,
                iranian_limit,
                false,
                false,
                None,
            );
        }
        if qtype == RecordType::A {
            spawn_siblings(
                &tx,
                &mut initial,
                Arc::clone(&self.recursors),
                &self.cache,
                name.clone(),
                recursion_limit,
            );
            let countries = self.geos.read().expect("geos").clone();
            for country in countries {
                spawn_geo(
                    &tx,
                    &mut initial,
                    Arc::clone(&self.geo_slots),
                    country,
                    name.clone(),
                );
            }
        }
        drop(tx);

        let mut bag = Bag::new(qtype);
        let mut initial_left = initial;
        let mut auth_started = false;
        let partial_at = tokio::time::Instant::now() + self.config.cold_wait();
        let mut published = false;
        let (auth_tx, mut auth_rx) = mpsc::unbounded_channel();
        loop {
            tokio::select! {
                biased;
                msg = rx.recv() => {
                    match msg {
                        Some(observation) => {
                            if initial_left > 0 {
                                initial_left -= 1;
                            }
                            bag.absorb(observation, &self.cache);
                            if initial_left == 0 && !auth_started {
                                auth_started = true;
                                self.spawn_authoritative(&name, qtype, &bag, &auth_tx);
                            }
                        }
                        None => break,
                    }
                }
                _ = sleep_until(partial_at), if !published => {
                    published = true;
                    if !bag.answers.is_empty() {
                        self.publish(&name, qtype, &bag);
                    }
                }
            }
        }
        while let Ok(observation) = auth_rx.try_recv() {
            bag.absorb(observation, &self.cache);
        }
        if !auth_started {
            self.spawn_authoritative(&name, qtype, &bag, &auth_tx);
        }
        drop(auth_tx);
        let auth_deadline = tokio::time::Instant::now()
            + Duration::from_millis(self.config.iranian_timeout_ms + 200);
        loop {
            tokio::select! {
                msg = auth_rx.recv() => {
                    match msg {
                        Some(observation) => bag.absorb(observation, &self.cache),
                        None => break,
                    }
                }
                _ = sleep_until(auth_deadline) => break,
            }
        }
        self.publish(&name, qtype, &bag);
        if qtype == RecordType::A {
            if let Some(zone) = siblings::registrable(&name) {
                self.cache.remember_sibling(&zone, &normalize(&name));
            }
        }
        self.probe_candidates(&name, &bag).await;
    }

    fn spawn_authoritative(
        self: &Arc<Self>,
        name: &Name,
        qtype: RecordType,
        bag: &Bag,
        tx: &mpsc::UnboundedSender<Observation>,
    ) {
        let prefixes = self.lists.read().expect("lists").ir_prefixes.clone();
        let mut targets = Vec::new();
        for ip in &bag.nameserver_ips {
            if let IpAddr::V4(ip) = ip {
                if in_iran(*ip, &prefixes) && !targets.contains(ip) {
                    targets.push(*ip);
                }
            }
        }
        for ip in targets.into_iter().take(AUTH_NS_CAP) {
            if self.cache.resolver_down(IpAddr::V4(ip)) {
                continue;
            }
            let tx = tx.clone();
            let name = name.clone();
            let limit = Duration::from_millis(self.config.iranian_timeout_ms);
            tokio::spawn(async move {
                let result = upstream::query(
                    SocketAddr::new(IpAddr::V4(ip), 53),
                    &name,
                    qtype,
                    false,
                    limit,
                )
                .await;
                let observation = match result {
                    QueryResult::Answer(message) => Observation::Answered(IpAddr::V4(ip), message),
                    QueryResult::Transport => Observation::Failed(IpAddr::V4(ip)),
                };
                let _ = tx.send(observation);
            });
        }
    }

    fn publish(&self, name: &Name, qtype: RecordType, bag: &Bag) {
        let qname = normalize(name);
        let code = u16::from(qtype);
        let previous = self.cache.get(&qname, code);
        let mut answers = previous
            .filter(|entry| !entry.negative)
            .map(|entry| entry.answers)
            .unwrap_or_default();
        for record in &bag.answers {
            let Some(stored) = store_record(record) else {
                continue;
            };
            if let Some(existing) = answers
                .iter_mut()
                .find(|existing| same_rdata(existing, &stored))
            {
                existing.ttl = stored.ttl;
            } else {
                answers.push(stored);
            }
        }
        if qtype == RecordType::A {
            let lists = self.lists.read().expect("lists");
            let addresses = ipv4_of_stored(&answers);
            if is_cloudflare(
                &bag.nameservers,
                &bag.cnames,
                &addresses,
                &lists.cf_prefixes,
            ) {
                for ip in &lists.senpai {
                    let record = Record::from_rdata(name.clone(), 300, RData::A(A(*ip)));
                    if let Some(stored) = store_record(&record) {
                        if !answers.iter().any(|existing| same_rdata(existing, &stored)) {
                            answers.push(stored);
                        }
                    }
                }
            }
            drop(lists);
            let (mut addresses, mut others): (Vec<_>, Vec<_>) = answers
                .into_iter()
                .partition(|record| record.rrtype == u16::from(RecordType::A));
            addresses.sort_by_key(|record| {
                ipv4_rdata(&record.rdata)
                    .map(|ip| rank_key(self.cache.probe(IpAddr::V4(ip))))
                    .unwrap_or((6, 0))
            });
            addresses.truncate(64);
            others.truncate(16);
            others.append(&mut addresses);
            answers = others;
        }
        if answers.is_empty() {
            self.cache.note_failure(&qname, code);
            return;
        }
        let additionals = if bag.saw_recursor {
            Some(
                bag.additionals
                    .iter()
                    .filter_map(store_record)
                    .take(MAX_ADDITIONAL_RECORDS)
                    .collect(),
            )
        } else {
            None
        };
        self.cache
            .merge_positive(&qname, code, answers, additionals);
    }

    async fn probe_candidates(self: &Arc<Self>, name: &Name, bag: &Bag) {
        let sni = normalize(name);
        let mut ips = ipv4_of_records(&bag.answers);
        ips.extend(self.lists.read().expect("lists").senpai.iter().copied());
        for ip in ips {
            if is_poison_v4(ip) || !self.cache.probe_due(IpAddr::V4(ip)) {
                continue;
            }
            let engine = Arc::clone(self);
            let sni = sni.clone();
            let permit = self.probes.clone().acquire_owned().await.ok();
            tokio::spawn(async move {
                let _permit = permit;
                let outcome =
                    probe::probe(IpAddr::V4(ip), &sni, engine.config.probe_timeout()).await;
                engine.cache.put_probe(IpAddr::V4(ip), outcome.score);
                if let Some(zone) = siblings::registrable_str(&sni) {
                    for san in outcome.sans {
                        engine.cache.remember_sibling(&zone, &san);
                    }
                }
            });
        }
    }

    fn entry_to_answer(&self, _name: &Name, qtype: RecordType, entry: &Entry) -> Answer {
        let fresh = cache::freshness(entry.expires_at, cache::now_secs());
        let mut records: Vec<Record> = entry
            .answers
            .iter()
            .filter_map(|stored| inflate(stored, cache::serve_ttl(stored.ttl, fresh)))
            .collect();
        if qtype == RecordType::A {
            let ips = records.iter().filter_map(record_v4).collect::<Vec<_>>();
            let ranked = select_addresses(&ips, |ip| self.cache.probe(IpAddr::V4(ip)));
            let mut cnames = Vec::new();
            let mut chosen = Vec::new();
            for record in records {
                match record.record_type() {
                    RecordType::CNAME => {
                        if cnames.len() < 4 {
                            cnames.push(record);
                        }
                    }
                    RecordType::A => {
                        if record_v4(&record).is_some_and(|ip| ranked.contains(&ip))
                            && chosen.len() < 10
                        {
                            chosen.push(record);
                        }
                    }
                    _ => {}
                }
            }
            chosen.sort_by_key(|record| {
                record_v4(record)
                    .map(|ip| rank_key(self.cache.probe(IpAddr::V4(ip))))
                    .unwrap_or((5, 0))
            });
            cnames.append(&mut chosen);
            records = cnames;
        } else {
            let cap = cap_for(qtype);
            records.retain(|record| {
                record.record_type() == qtype || record.record_type() == RecordType::CNAME
            });
            if records.len() > cap {
                records.truncate(cap);
            }
        }
        let additionals = entry
            .additionals
            .iter()
            .filter_map(|stored| inflate(stored, cache::serve_ttl(stored.ttl, fresh)))
            .take(fit_additionals(records.len()))
            .collect();
        Answer {
            answers: records,
            additionals,
            nxdomain: false,
        }
    }

    async fn list_loop(self: Arc<Self>) {
        loop {
            self.refresh_lists().await;
            tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
        }
    }

    async fn geo_loop(self: Arc<Self>) {
        loop {
            self.refresh_geos().await;
            tokio::time::sleep(Duration::from_secs(30 * 60)).await;
        }
    }

    async fn refresh_geos(&self) {
        let Some(index) = fetch(&self.http, geo::COUNTRY_INDEX).await else {
            tracing::warn!("geo: country index unavailable");
            return;
        };
        let countries = geo::parse_country_index(&index);
        if countries.is_empty() {
            tracing::warn!("geo: country index had no directories");
            return;
        }
        let previous = self.geos.read().expect("geos").clone();
        let gate = Arc::new(Semaphore::new(8));
        let mut tasks = Vec::new();
        for country in countries {
            let http = self.http.clone();
            let gate = Arc::clone(&gate);
            let kept = previous.iter().find(|known| known.code == country).cloned();
            tasks.push(tokio::spawn(async move {
                let _permit = gate.acquire_owned().await.expect("geo scan slots");
                let Some(text) = fetch(&http, &geo::country_url(&country)).await else {
                    return kept;
                };
                let proxies = geo::parse_proxy_list(&text);
                if proxies.is_empty() {
                    return kept;
                }
                Some(Country {
                    code: country,
                    proxies,
                })
            }));
        }
        let mut selected = Vec::new();
        for task in tasks {
            if let Ok(Some(country)) = task.await {
                selected.push(country);
            }
        }
        if selected.is_empty() {
            tracing::warn!("geo: proxy lists unavailable");
            return;
        }
        geo::store_snapshot(&self.config.data_dir, &selected);
        tracing::info!(countries = selected.len(), "geo: proxy lists refreshed");
        *self.geos.write().expect("geos") = selected;
    }

    async fn refresh_lists(&self) {
        let dir = self.config.data_dir.clone();
        if let Some(text) = fetch(
            &self.http,
            "https://www.ipdeny.com/ipblocks/data/countries/ir.zone",
        )
        .await
        {
            let prefixes = lists::parse_prefixes(&text);
            if !prefixes.is_empty() {
                let _ = std::fs::write(dir.join("ir.zone"), text);
                self.lists.write().expect("lists").ir_prefixes = prefixes;
            }
        }
        if let Some(text) = fetch(&self.http, "https://www.cloudflare.com/ips-v4").await {
            let prefixes = lists::parse_prefixes(&text);
            if !prefixes.is_empty() {
                let _ = std::fs::write(dir.join("cloudflare-ipv4.txt"), text);
                self.lists.write().expect("lists").cf_prefixes = prefixes;
            }
        }
        if let Some(text) = fetch(&self.http, "https://public-dns.info/nameserver/ir.csv").await {
            let mut resolvers = Lists::vendored().resolvers;
            for ip in lists::parse_ir_csv(&text) {
                let addr = SocketAddr::new(ip, 53);
                if !resolvers.contains(&addr) {
                    resolvers.push(addr);
                }
            }
            lists::write_resolvers(&dir.join("iranian-resolvers.txt"), &resolvers);
            self.lists.write().expect("lists").resolvers = resolvers;
        }
        if let Ok(text) = std::fs::read_to_string(dir.join("cloudflare-ips.txt")) {
            self.lists.write().expect("lists").senpai = lists::parse_ipv4s(&text);
        }
        if let Some(text) = self.fetch_signed(lists::PUBLIC_RESOLVER_URLS).await {
            let _ = std::fs::write(dir.join("public-resolvers.md"), text);
        }
        if let Some(text) = self.fetch_signed(lists::RELAY_URLS).await {
            let _ = std::fs::write(dir.join("relays.md"), text);
        }
        let discovered = lists::load_discovered(&dir);
        self.lists.write().expect("lists").discovered = discovered;
    }

    async fn fetch_signed(&self, urls: &[&str]) -> Option<String> {
        for url in urls {
            let Some(body) = fetch(&self.http, url).await else {
                continue;
            };
            let Some(signature) = fetch(&self.http, &format!("{url}.minisig")).await else {
                continue;
            };
            if lists::signature_ok(body.as_bytes(), &signature)
                && !lists::parse_stamp_list(&body).is_empty()
            {
                return Some(body);
            }
        }
        None
    }
}

fn spawn_recursion(
    tx: &mpsc::UnboundedSender<Observation>,
    count: &mut usize,
    recursors: Arc<Recursors>,
    mut name: Name,
    qtype: RecordType,
    limit: Duration,
    nameserver_lookup: bool,
) {
    *count += 1;
    if !name.is_fqdn() {
        name.set_fqdn(true);
    }
    let tx = tx.clone();
    tokio::spawn(async move {
        let query = Query::query(name.clone(), qtype);
        let result = tokio::time::timeout(
            limit,
            recursors
                .for_name(&name)
                .resolve(query, std::time::Instant::now(), false),
        )
        .await;
        let observation = match result {
            Ok(Ok(message)) if nameserver_lookup => Observation::Names(message),
            Ok(Ok(message)) => Observation::Recursor(message),
            _ => Observation::RecursionMiss,
        };
        let _ = tx.send(observation);
    });
}

fn spawn_siblings(
    tx: &mpsc::UnboundedSender<Observation>,
    count: &mut usize,
    recursors: Arc<Recursors>,
    cache: &Cache,
    name: Name,
    limit: Duration,
) {
    let known = siblings::registrable(&name)
        .map(|zone| cache.siblings_of(&zone))
        .unwrap_or_default();
    for related in siblings::related_names(&name, &known) {
        *count += 1;
        let tx = tx.clone();
        let recursors = Arc::clone(&recursors);
        let original = name.clone();
        tokio::spawn(async move {
            let query = Query::query(related.clone(), RecordType::A);
            let result = tokio::time::timeout(
                limit,
                recursors
                    .for_name(&related)
                    .resolve(query, std::time::Instant::now(), false),
            )
            .await;
            let observation = match result {
                Ok(Ok(mut message)) => {
                    message.answers = message
                        .answers
                        .iter()
                        .filter_map(|record| {
                            let ip = record_v4(record)?;
                            if is_poison_v4(ip) {
                                return None;
                            }
                            Some(Record::from_rdata(
                                original.clone(),
                                record.ttl,
                                RData::A(A(ip)),
                            ))
                        })
                        .collect();
                    message.authorities.clear();
                    message.additionals.clear();
                    Observation::Sibling(message)
                }
                _ => Observation::RecursionMiss,
            };
            let _ = tx.send(observation);
        });
    }
}

fn spawn_geo(
    tx: &mpsc::UnboundedSender<Observation>,
    count: &mut usize,
    slots: Arc<Semaphore>,
    country: Country,
    mut name: Name,
) {
    *count += 1;
    if !name.is_fqdn() {
        name.set_fqdn(true);
    }
    let tx = tx.clone();
    tokio::spawn(async move {
        let _permit = slots.acquire_owned().await.expect("geo slots");
        let observation =
            match geo::query_country(&country.proxies, &name, geo::QUERY_TIMEOUT).await {
                Some(message) => Observation::Geo(geo::rewrite_a(&message, &name)),
                None => {
                    tracing::debug!(country = %country.code, "geo query failed");
                    Observation::RecursionMiss
                }
            };
        let _ = tx.send(observation);
    });
}

fn spawn_query(
    tx: &mpsc::UnboundedSender<Observation>,
    count: &mut usize,
    server: SocketAddr,
    name: Name,
    qtype: RecordType,
    recursion_desired: bool,
    limit: Duration,
    recursor: bool,
    nameserver_lookup: bool,
    gate: Option<Arc<Semaphore>>,
) {
    *count += 1;
    let tx = tx.clone();
    tokio::spawn(async move {
        let _permit = match gate {
            Some(sem) => Some(sem.acquire_owned().await.expect("discovery slots")),
            None => None,
        };
        let result = upstream::query(server, &name, qtype, recursion_desired, limit).await;
        let observation = match result {
            QueryResult::Answer(message) if nameserver_lookup => Observation::Names(message),
            QueryResult::Answer(message) if recursor => Observation::Recursor(message),
            QueryResult::Answer(message) => Observation::Answered(server.ip(), message),
            QueryResult::Transport => Observation::Failed(server.ip()),
        };
        let _ = tx.send(observation);
    });
}

#[derive(Default)]
struct Bag {
    wanted: Option<RecordType>,
    answers: Vec<Record>,
    additionals: Vec<Record>,
    nameservers: Vec<String>,
    nameserver_ips: Vec<IpAddr>,
    cnames: Vec<String>,
    saw_recursor: bool,
}

impl Bag {
    fn new(wanted: RecordType) -> Self {
        Self {
            wanted: Some(wanted),
            ..Self::default()
        }
    }

    fn absorb(&mut self, observation: Observation, cache: &Cache) {
        match observation {
            Observation::Failed(ip) => cache.mark_resolver(ip, true),
            Observation::Recursor(message) => {
                self.saw_recursor = true;
                self.take_message(&message, true);
            }
            Observation::Names(message) => self.take_ns(&message),
            Observation::Answered(ip, message) => {
                cache.mark_resolver(ip, false);
                self.take_message(&message, false);
            }
            Observation::RecursionMiss => {}
            Observation::Sibling(message) | Observation::Geo(message) => {
                self.take_message(&message, false);
            }
        }
    }

    fn take_message(&mut self, message: &Message, with_additional: bool) {
        if message.metadata.response_code == ResponseCode::NXDomain && message.answers.is_empty() {
            return;
        }
        for record in &message.answers {
            self.keep_answer(record);
        }
        if with_additional {
            for record in message.authorities.iter().chain(&message.additionals) {
                if record.record_type() == RecordType::NS {
                    self.keep_ns(record);
                }
            }
            for record in &message.additionals {
                if matches!(record.record_type(), RecordType::A | RecordType::AAAA)
                    && !is_poison_record(record)
                {
                    self.additionals.push(record.clone());
                    if let Some(ip) = record_v4(record) {
                        self.nameserver_ips.push(IpAddr::V4(ip));
                    }
                }
            }
        }
    }

    fn take_ns(&mut self, message: &Message) {
        for record in message.answers.iter().chain(&message.authorities) {
            if record.record_type() == RecordType::NS {
                self.keep_ns(record);
            }
        }
        for record in &message.additionals {
            if let Some(ip) = record_v4(record) {
                if !is_poison_v4(ip) {
                    self.nameserver_ips.push(IpAddr::V4(ip));
                }
            }
        }
    }

    fn keep_answer(&mut self, record: &Record) {
        if is_poison_record(record) {
            return;
        }
        if self.wanted.is_some_and(|wanted| {
            record.record_type() != wanted && record.record_type() != RecordType::CNAME
        }) {
            return;
        }
        if record.record_type() == RecordType::CNAME {
            self.cnames.push(normalize(record.data_name()));
        }
        if !self
            .answers
            .iter()
            .any(|existing| same_wire(existing, record))
        {
            self.answers.push(record.clone());
        }
    }

    fn keep_ns(&mut self, record: &Record) {
        if let Some(name) = ns_target(record) {
            let text = normalize(&name);
            if !self.nameservers.contains(&text) {
                self.nameservers.push(text);
            }
        }
    }
}

fn same_rdata(left: &StoredRecord, right: &StoredRecord) -> bool {
    left.owner == right.owner && left.rrtype == right.rrtype && left.rdata == right.rdata
}

fn same_wire(left: &Record, right: &Record) -> bool {
    left.record_type() == right.record_type()
        && normalize(&left.name) == normalize(&right.name)
        && rdata_bytes(left) == rdata_bytes(right)
}

fn store_record(record: &Record) -> Option<StoredRecord> {
    Some(StoredRecord {
        owner: normalize(&record.name),
        rrtype: u16::from(record.record_type()),
        rdata: rdata_bytes(record)?,
        ttl: record.ttl,
    })
}

fn rdata_bytes(record: &Record) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut encoder = BinEncoder::new(&mut bytes);
    record.data.emit(&mut encoder).ok()?;
    Some(bytes)
}

fn inflate(stored: &StoredRecord, ttl: u32) -> Option<Record> {
    let name = Name::from_utf8(&stored.owner).ok()?;
    let rrtype = RecordType::from(stored.rrtype);
    let mut decoder = hickory_proto::serialize::binary::BinDecoder::new(&stored.rdata);
    let rdata = RData::read(
        &mut decoder,
        rrtype,
        Restrict::new(stored.rdata.len() as u16),
    )
    .ok()?;
    Some(Record::from_rdata(name, ttl, rdata))
}

fn normalize(name: &Name) -> String {
    let mut text = name.to_string().to_ascii_lowercase();
    if !text.ends_with('.') {
        text.push('.');
    }
    text
}

fn record_v4(record: &Record) -> Option<Ipv4Addr> {
    match record.data.ip_addr() {
        Some(IpAddr::V4(ip)) => Some(ip),
        _ => None,
    }
}

fn ipv4_rdata(bytes: &[u8]) -> Option<Ipv4Addr> {
    if bytes.len() == 4 {
        Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    } else {
        None
    }
}

fn ipv4_of_stored(records: &[StoredRecord]) -> Vec<Ipv4Addr> {
    records
        .iter()
        .filter_map(|record| {
            if record.rrtype == u16::from(RecordType::A) {
                ipv4_rdata(&record.rdata)
            } else {
                None
            }
        })
        .collect()
}

fn ipv4_of_records(records: &[Record]) -> Vec<Ipv4Addr> {
    records.iter().filter_map(record_v4).collect()
}

fn is_poison_record(record: &Record) -> bool {
    record_v4(record).is_some_and(is_poison_v4)
}

fn ns_target(record: &Record) -> Option<Name> {
    match &record.data {
        RData::NS(NS(name)) => Some(name.clone()),
        _ => None,
    }
}

trait DataName {
    fn data_name(&self) -> &Name;
}

impl DataName for Record {
    fn data_name(&self) -> &Name {
        match &self.data {
            RData::CNAME(CNAME(name)) | RData::NS(NS(name)) => name,
            _ => &self.name,
        }
    }
}

fn cap_for(qtype: RecordType) -> usize {
    match qtype {
        RecordType::A | RecordType::AAAA => 10,
        RecordType::NS
        | RecordType::MX
        | RecordType::TXT
        | RecordType::HTTPS
        | RecordType::SVCB => 8,
        RecordType::CNAME | RecordType::PTR => 4,
        RecordType::SOA => 2,
        _ => 8,
    }
}

fn fit_additionals(answer_count: usize) -> usize {
    MAX_ADDITIONAL_RECORDS.saturating_sub(answer_count / 4)
}

async fn fetch(http: &reqwest::Client, url: &str) -> Option<String> {
    let response = http.get(url).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.text().await.ok()
}
