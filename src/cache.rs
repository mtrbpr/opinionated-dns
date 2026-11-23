use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, params};

use crate::rank::ProbeScore;

pub const STALE_TTL: u32 = 30;
pub const MIN_TTL: u32 = 300;
pub const MAX_TTL: u32 = 86_400;
const MAX_STORED_ANSWERS: usize = 64;

#[derive(Clone, Debug)]
pub struct StoredRecord {
    pub owner: String,
    pub rrtype: u16,
    pub rdata: Vec<u8>,
    pub ttl: u32,
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub answers: Vec<StoredRecord>,
    pub additionals: Vec<StoredRecord>,
    pub expires_at: i64,
    pub retry_not_before: i64,
    pub negative: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freshness {
    Fresh,
    Stale,
}

pub fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn freshness(expires_at: i64, now: i64) -> Freshness {
    if now < expires_at {
        Freshness::Fresh
    } else {
        Freshness::Stale
    }
}

pub fn serve_ttl(stored: u32, fresh: Freshness) -> u32 {
    match fresh {
        Freshness::Stale => STALE_TTL,
        Freshness::Fresh => stored.clamp(MIN_TTL, MAX_TTL),
    }
}

/// A cached name is answered immediately, whether or not its TTL has passed.
pub fn answers_immediately(entry: Option<&Entry>) -> bool {
    entry.is_some_and(|entry| !entry.answers.is_empty() || entry.negative)
}

pub struct Cache {
    mem: Mutex<HashMap<(String, u16), Entry>>,
    probes: Mutex<HashMap<IpAddr, (ProbeScore, i64)>>,
    health: Mutex<HashMap<IpAddr, i64>>,
    siblings: Mutex<HashMap<String, Vec<String>>>,
    conn: Mutex<Connection>,
}

impl Cache {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS records (
                qname TEXT NOT NULL,
                qtype INTEGER NOT NULL,
                section TEXT NOT NULL,
                owner TEXT NOT NULL,
                rrtype INTEGER NOT NULL,
                rdata BLOB NOT NULL,
                ttl INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                retry_not_before INTEGER NOT NULL,
                negative INTEGER NOT NULL,
                PRIMARY KEY (qname, qtype, section, owner, rrtype, rdata)
            );
            CREATE TABLE IF NOT EXISTS probes (
                ip TEXT PRIMARY KEY,
                tcp80_ms INTEGER,
                tcp443_ms INTEGER,
                tls_ms INTEGER,
                tls_verified INTEGER NOT NULL,
                http_ms INTEGER,
                checked_at INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS health (
                ip TEXT PRIMARY KEY,
                failed_until INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS siblings (
                registrable TEXT NOT NULL,
                name TEXT NOT NULL,
                PRIMARY KEY (registrable, name)
            );
            ",
        )?;
        let cache = Self {
            mem: Mutex::new(HashMap::new()),
            probes: Mutex::new(HashMap::new()),
            health: Mutex::new(HashMap::new()),
            siblings: Mutex::new(HashMap::new()),
            conn: Mutex::new(conn),
        };
        cache.load()?;
        Ok(cache)
    }

    fn load(&self) -> rusqlite::Result<()> {
        let conn = self.conn.lock().expect("sqlite");
        let mut stmt = conn.prepare(
            "SELECT qname, qtype, section, owner, rrtype, rdata, ttl, expires_at, retry_not_before, negative
             FROM records",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u16>(1)?,
                row.get::<_, String>(2)?,
                StoredRecord {
                    owner: row.get(3)?,
                    rrtype: row.get(4)?,
                    rdata: row.get(5)?,
                    ttl: row.get::<_, i64>(6)? as u32,
                },
                row.get::<_, i64>(7)?,
                row.get::<_, i64>(8)?,
                row.get::<_, i64>(9)? != 0,
            ))
        })?;
        let mut mem = self.mem.lock().expect("memory");
        for row in rows {
            let (qname, qtype, section, record, expires_at, retry_not_before, negative) = row?;
            let entry = mem.entry((qname, qtype)).or_insert_with(|| Entry {
                answers: Vec::new(),
                additionals: Vec::new(),
                expires_at,
                retry_not_before,
                negative,
            });
            entry.expires_at = entry.expires_at.min(expires_at);
            entry.retry_not_before = entry.retry_not_before.max(retry_not_before);
            entry.negative = negative && entry.answers.is_empty();
            match section.as_str() {
                "additional" => entry.additionals.push(record),
                _ if !negative => {
                    entry.negative = false;
                    entry.answers.push(record);
                }
                _ => {}
            }
        }
        drop(stmt);

        let mut probe_stmt = conn.prepare(
            "SELECT ip, tcp80_ms, tcp443_ms, tls_ms, tls_verified, http_ms, checked_at FROM probes",
        )?;
        let probe_rows = probe_stmt.query_map([], |row| {
            let ip: String = row.get(0)?;
            let score = ProbeScore {
                tcp80_ms: row.get::<_, Option<i64>>(1)?.map(|v| v as u32),
                tcp443_ms: row.get::<_, Option<i64>>(2)?.map(|v| v as u32),
                tls_ms: row.get::<_, Option<i64>>(3)?.map(|v| v as u32),
                tls_verified: row.get::<_, i64>(4)? != 0,
                http_ms: row.get::<_, Option<i64>>(5)?.map(|v| v as u32),
            };
            let checked_at: i64 = row.get(6)?;
            Ok((ip, score, checked_at))
        })?;
        let mut probes = self.probes.lock().expect("probes");
        for row in probe_rows {
            let (ip, score, checked_at) = row?;
            if let Ok(ip) = ip.parse() {
                probes.insert(ip, (score, checked_at));
            }
        }
        drop(probe_stmt);

        let mut health_stmt = conn.prepare("SELECT ip, failed_until FROM health")?;
        let health_rows = health_stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        let mut health = self.health.lock().expect("health");
        for row in health_rows {
            let (ip, until) = row?;
            if let Ok(ip) = ip.parse() {
                health.insert(ip, until);
            }
        }
        drop(health_stmt);

        let mut sibling_stmt = conn.prepare("SELECT registrable, name FROM siblings")?;
        let sibling_rows = sibling_stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut siblings = self.siblings.lock().expect("siblings");
        for row in sibling_rows {
            let (registrable, name) = row?;
            siblings.entry(registrable).or_default().push(name);
        }
        Ok(())
    }

    pub fn siblings_of(&self, registrable: &str) -> Vec<String> {
        self.siblings
            .lock()
            .expect("siblings")
            .get(registrable)
            .cloned()
            .unwrap_or_default()
    }

    pub fn remember_sibling(&self, registrable: &str, name: &str) {
        let Some(registrable) = crate::siblings::clean_host(registrable) else {
            return;
        };
        let Some(name) = crate::siblings::clean_host(name) else {
            return;
        };
        let mut siblings = self.siblings.lock().expect("siblings");
        let names = siblings.entry(registrable.clone()).or_default();
        if names.iter().any(|existing| existing == &name) || names.len() >= 64 {
            return;
        }
        names.push(name.clone());
        drop(siblings);
        let conn = self.conn.lock().expect("sqlite");
        let _ = conn.execute(
            "INSERT OR IGNORE INTO siblings (registrable, name) VALUES (?1, ?2)",
            params![registrable, name],
        );
    }

    pub fn get(&self, qname: &str, qtype: u16) -> Option<Entry> {
        self.mem
            .lock()
            .expect("memory")
            .get(&(qname.to_string(), qtype))
            .cloned()
    }

    pub fn probe(&self, ip: IpAddr) -> Option<ProbeScore> {
        self.probes
            .lock()
            .expect("probes")
            .get(&ip)
            .map(|(score, _)| *score)
    }

    pub fn probe_due(&self, ip: IpAddr) -> bool {
        self.probes
            .lock()
            .expect("probes")
            .get(&ip)
            .map(|(_, checked_at)| now_secs() - checked_at > 6 * 3600)
            .unwrap_or(true)
    }

    pub fn resolver_down(&self, ip: IpAddr) -> bool {
        self.health
            .lock()
            .expect("health")
            .get(&ip)
            .is_some_and(|until| *until > now_secs())
    }

    pub fn mark_resolver(&self, ip: IpAddr, failed: bool) {
        let until = if failed { now_secs() + 86_400 } else { 0 };
        if failed {
            self.health.lock().expect("health").insert(ip, until);
        } else {
            self.health.lock().expect("health").remove(&ip);
        }
        let conn = self.conn.lock().expect("sqlite");
        if failed {
            let _ = conn.execute(
                "INSERT INTO health (ip, failed_until) VALUES (?1, ?2)
                 ON CONFLICT(ip) DO UPDATE SET failed_until = excluded.failed_until",
                params![ip.to_string(), until],
            );
        } else {
            let _ = conn.execute("DELETE FROM health WHERE ip = ?1", params![ip.to_string()]);
        }
    }

    pub fn put_probe(&self, ip: IpAddr, score: ProbeScore) {
        let checked_at = now_secs();
        self.probes
            .lock()
            .expect("probes")
            .insert(ip, (score, checked_at));
        let conn = self.conn.lock().expect("sqlite");
        let _ = conn.execute(
            "INSERT INTO probes (ip, tcp80_ms, tcp443_ms, tls_ms, tls_verified, http_ms, checked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(ip) DO UPDATE SET
               tcp80_ms = excluded.tcp80_ms,
               tcp443_ms = excluded.tcp443_ms,
               tls_ms = excluded.tls_ms,
               tls_verified = excluded.tls_verified,
               http_ms = excluded.http_ms,
               checked_at = excluded.checked_at",
            params![
                ip.to_string(),
                score.tcp80_ms.map(|v| v as i64),
                score.tcp443_ms.map(|v| v as i64),
                score.tls_ms.map(|v| v as i64),
                if score.tls_verified { 1 } else { 0 },
                score.http_ms.map(|v| v as i64),
                checked_at,
            ],
        );
    }

    /// Replace the stored set with this observation. An empty answer list never erases a positive entry.
    pub fn merge_positive(
        &self,
        qname: &str,
        qtype: u16,
        mut answers: Vec<StoredRecord>,
        additionals: Option<Vec<StoredRecord>>,
    ) {
        if answers.is_empty() {
            self.note_failure(qname, qtype);
            return;
        }
        answers.truncate(MAX_STORED_ANSWERS);
        let now = now_secs();
        let min_ttl = answers.iter().map(|record| record.ttl).min().unwrap_or(30);
        let expires_at = now + i64::from(min_ttl.max(30));
        let mut mem = self.mem.lock().expect("memory");
        let entry = mem
            .entry((qname.to_string(), qtype))
            .or_insert_with(|| Entry {
                answers: Vec::new(),
                additionals: Vec::new(),
                expires_at,
                retry_not_before: expires_at,
                negative: false,
            });
        entry.negative = false;
        entry.expires_at = expires_at;
        entry.retry_not_before = expires_at;
        entry.answers = answers;
        if let Some(additionals) = additionals {
            entry.additionals = additionals;
        }
        let stored = entry.clone();
        drop(mem);
        self.write_entry(qname, qtype, &stored);
    }

    pub fn note_failure(&self, qname: &str, qtype: u16) {
        let now = now_secs();
        let mut mem = self.mem.lock().expect("memory");
        if let Some(entry) = mem.get_mut(&(qname.to_string(), qtype)) {
            if !entry.answers.is_empty() {
                entry.retry_not_before = now + 60;
                let stored = entry.clone();
                drop(mem);
                self.write_entry(qname, qtype, &stored);
                return;
            }
        }
        let entry = Entry {
            answers: Vec::new(),
            additionals: Vec::new(),
            expires_at: now + 30,
            retry_not_before: now + 30,
            negative: true,
        };
        mem.insert((qname.to_string(), qtype), entry.clone());
        drop(mem);
        self.write_entry(qname, qtype, &entry);
    }

    fn write_entry(&self, qname: &str, qtype: u16, entry: &Entry) {
        let conn = self.conn.lock().expect("sqlite");
        let _ = conn.execute(
            "DELETE FROM records WHERE qname = ?1 AND qtype = ?2",
            params![qname, qtype],
        );
        if entry.negative && entry.answers.is_empty() {
            let _ = conn.execute(
                "INSERT INTO records (qname, qtype, section, owner, rrtype, rdata, ttl, expires_at, retry_not_before, negative)
                 VALUES (?1, ?2, 'negative', '', 0, x'', 0, ?3, ?4, 1)",
                params![qname, qtype, entry.expires_at, entry.retry_not_before],
            );
            return;
        }
        for (section, records) in [
            ("answer", &entry.answers),
            ("additional", &entry.additionals),
        ] {
            for record in records {
                let _ = conn.execute(
                    "INSERT OR REPLACE INTO records
                     (qname, qtype, section, owner, rrtype, rdata, ttl, expires_at, retry_not_before, negative)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0)",
                    params![
                        qname,
                        qtype,
                        section,
                        record.owner,
                        record.rrtype,
                        record.rdata,
                        record.ttl,
                        entry.expires_at,
                        entry.retry_not_before,
                    ],
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_ttl_is_clamped_and_stale_ttl_is_short() {
        assert_eq!(serve_ttl(10, Freshness::Fresh), MIN_TTL);
        assert_eq!(serve_ttl(600, Freshness::Fresh), 600);
        assert_eq!(serve_ttl(1_000_000, Freshness::Fresh), MAX_TTL);
        assert_eq!(serve_ttl(600, Freshness::Stale), STALE_TTL);
    }

    #[test]
    fn a_stored_answer_is_served_immediately_even_when_stale() {
        let entry = Entry {
            answers: vec![StoredRecord {
                owner: "example.com.".into(),
                rrtype: 1,
                rdata: vec![1, 2, 3, 4],
                ttl: 60,
            }],
            additionals: Vec::new(),
            expires_at: 1,
            retry_not_before: 1,
            negative: false,
        };
        assert_eq!(freshness(entry.expires_at, 10_000), Freshness::Stale);
        assert!(answers_immediately(Some(&entry)));
        assert!(!answers_immediately(None));
    }

    #[test]
    fn failure_does_not_erase_a_positive_entry() {
        let path = std::env::temp_dir().join(format!(
            "opinionated-dns-cache-{}.sqlite",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let cache = Cache::open(&path).unwrap();
        cache.merge_positive(
            "example.com.",
            1,
            vec![StoredRecord {
                owner: "example.com.".into(),
                rrtype: 1,
                rdata: vec![8, 8, 8, 8],
                ttl: 60,
            }],
            None,
        );
        cache.note_failure("example.com.", 1);
        let entry = cache.get("example.com.", 1).unwrap();
        assert!(!entry.negative);
        assert_eq!(entry.answers.len(), 1);
        assert_eq!(entry.answers[0].rdata, vec![8, 8, 8, 8]);
        let _ = std::fs::remove_file(&path);
    }
}
