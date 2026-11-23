//! Proxy lists per country, so an A lookup can see answers that public
//! resolvers only give to clients in that country. A proxy is checked when
//! the query runs. The list refresh does not decide which one is healthy.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinDecodable;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, RootCertStore, SignatureScheme};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::poison::is_poison_v4;
use crate::upstream;

pub const COUNTRY_INDEX: &str =
    "https://api.github.com/repos/iplocate/free-proxy-list/contents/countries";
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(8);
pub const MAX_PROXY_TRIES: usize = 12;

const INDEX_URL: &str = "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/countries";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    Socks5,
    Socks4,
    Http,
    Https,
}

impl Scheme {
    fn rank(self) -> u8 {
        match self {
            Scheme::Socks5 => 0,
            Scheme::Socks4 => 1,
            Scheme::Http => 2,
            Scheme::Https => 3,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Scheme::Socks5 => "socks5",
            Scheme::Socks4 => "socks4",
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "socks5" => Some(Scheme::Socks5),
            "socks4" => Some(Scheme::Socks4),
            "http" => Some(Scheme::Http),
            "https" => Some(Scheme::Https),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proxy {
    pub scheme: Scheme,
    pub addr: SocketAddr,
}

impl std::fmt::Display for Proxy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}://{}", self.scheme.as_str(), self.addr)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Doh,
    Dot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Transport {
    pub kind: Kind,
    pub addr: SocketAddr,
}

impl Transport {
    fn candidates() -> [Self; 4] {
        [
            Self {
                kind: Kind::Doh,
                addr: SocketAddr::from(([1, 1, 1, 1], 443)),
            },
            Self {
                kind: Kind::Doh,
                addr: SocketAddr::from(([8, 8, 8, 8], 443)),
            },
            Self {
                kind: Kind::Dot,
                addr: SocketAddr::from(([1, 1, 1, 1], 853)),
            },
            Self {
                kind: Kind::Dot,
                addr: SocketAddr::from(([8, 8, 8, 8], 853)),
            },
        ]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Country {
    pub code: String,
    pub proxies: Vec<Proxy>,
}

pub fn country_url(country: &str) -> String {
    format!("{INDEX_URL}/{country}/proxies.txt")
}

pub fn parse_proxy_line(line: &str) -> Option<Proxy> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let (scheme, rest) = line.split_once("://")?;
    let scheme = Scheme::parse(&scheme.to_ascii_lowercase())?;
    let addr = rest.parse().ok()?;
    Some(Proxy { scheme, addr })
}

pub fn parse_proxy_list(text: &str) -> Vec<Proxy> {
    let mut proxies: Vec<Proxy> = text.lines().filter_map(parse_proxy_line).collect();
    proxies.sort_by_key(|proxy| proxy.scheme.rank());
    proxies
}

pub fn parse_country_index(text: &str) -> Vec<String> {
    let mut codes = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("\"name\"") {
        rest = &rest[start + "\"name\"".len()..];
        let Some(after_colon) = rest.find(':') else {
            break;
        };
        rest = &rest[after_colon + 1..];
        let Some(open) = rest.find('"') else {
            break;
        };
        rest = &rest[open + 1..];
        let Some(close) = rest.find('"') else {
            break;
        };
        let name = &rest[..close];
        rest = &rest[close + 1..];
        let next = rest.find("\"name\"").unwrap_or(rest.len());
        let window = &rest[..next];
        if is_country(name) && window.contains("\"dir\"") && !codes.iter().any(|code| code == name)
        {
            codes.push(name.to_string());
        }
    }
    codes
}

pub fn parse_snapshot_line(line: &str) -> Option<(String, Proxy)> {
    let mut parts = line.split_whitespace();
    let country = parts.next()?;
    if !is_country(country) {
        return None;
    }
    let proxy = parse_proxy_line(parts.next()?)?;
    Some((country.to_string(), proxy))
}

const EMBEDDED_PROXIES: &str = include_str!("../static/geo-proxies.txt");

pub fn load_snapshot(dir: &Path) -> Vec<Country> {
    let text = std::fs::read_to_string(dir.join("geo-proxies.txt"))
        .ok()
        .filter(|text| !text.trim().is_empty())
        .unwrap_or_else(|| EMBEDDED_PROXIES.to_string());
    group_proxies(text.lines().filter_map(parse_snapshot_line))
}

pub fn store_snapshot(dir: &Path, countries: &[Country]) {
    let mut lines = Vec::new();
    for country in countries {
        for proxy in &country.proxies {
            lines.push(format!("{} {proxy}", country.code));
        }
    }
    lines.sort();
    if !lines.is_empty() {
        lines.push(String::new());
    }
    let _ = std::fs::write(dir.join("geo-proxies.txt"), lines.join("\n"));
}

fn group_proxies(lines: impl IntoIterator<Item = (String, Proxy)>) -> Vec<Country> {
    let mut countries: Vec<Country> = Vec::new();
    for (code, proxy) in lines {
        if let Some(country) = countries.iter_mut().find(|country| country.code == code) {
            country.proxies.push(proxy);
        } else {
            countries.push(Country {
                code,
                proxies: vec![proxy],
            });
        }
    }
    for country in &mut countries {
        country.proxies.sort_by_key(|proxy| proxy.scheme.rank());
    }
    countries
}

fn is_country(name: &str) -> bool {
    name.len() == 2 && name.bytes().all(|byte| byte.is_ascii_uppercase())
}

pub fn usable_answer(message: &Message) -> bool {
    if message.metadata.message_type != MessageType::Response {
        return false;
    }
    if !matches!(
        message.metadata.response_code,
        ResponseCode::NoError | ResponseCode::NXDomain
    ) {
        return false;
    }
    let addresses: Vec<Ipv4Addr> = message.answers.iter().filter_map(record_v4).collect();
    addresses.is_empty() || addresses.iter().any(|ip| !is_poison_v4(*ip))
}

pub fn rewrite_a(message: &Message, qname: &Name) -> Message {
    let mut out = Message::new(message.metadata.id, MessageType::Response, OpCode::Query);
    out.metadata.response_code = message.metadata.response_code;
    let mut seen = Vec::new();
    for record in &message.answers {
        let Some(ip) = record_v4(record) else {
            continue;
        };
        if is_poison_v4(ip) || seen.contains(&ip) {
            continue;
        }
        seen.push(ip);
        out.answers.push(Record::from_rdata(
            qname.clone(),
            record.ttl,
            RData::A(A(ip)),
        ));
    }
    out
}

pub async fn query_country(proxies: &[Proxy], name: &Name, limit: Duration) -> Option<Message> {
    let mut failures = 0usize;
    for proxy in proxies {
        if failures >= MAX_PROXY_TRIES {
            break;
        }
        let started = std::time::Instant::now();
        let mut answered = None;
        for transport in Transport::candidates() {
            let remaining = limit.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                break;
            }
            match timeout(remaining, exchange(proxy, transport, name, RecordType::A)).await {
                Ok(Some(message)) if usable_answer(&message) => {
                    answered = Some(message);
                    break;
                }
                _ => {}
            }
        }
        if let Some(message) = answered {
            return Some(message);
        }
        failures += 1;
    }
    None
}

pub async fn exchange(
    proxy: &Proxy,
    transport: Transport,
    name: &Name,
    qtype: RecordType,
) -> Option<Message> {
    let mut name = name.clone();
    if !name.is_fqdn() {
        name.set_fqdn(true);
    }
    let query = upstream::build_query(&name, qtype, true).ok()?;
    let raw = tunnel(proxy, transport.addr).await?;
    let server_name = ServerName::from(transport.addr.ip()).to_owned();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(verified_config()?));
    let mut tls = connector.connect(server_name, raw).await.ok()?;
    match transport.kind {
        Kind::Doh => doh_exchange(&mut tls, transport.addr, &query).await,
        Kind::Dot => dot_exchange(&mut tls, &query).await,
    }
}

enum Io {
    Tcp(TcpStream),
    Socks5(tokio_socks::tcp::Socks5Stream<TcpStream>),
    Socks4(tokio_socks::tcp::Socks4Stream<TcpStream>),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl AsyncRead for Io {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Io::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            Io::Socks5(stream) => Pin::new(stream).poll_read(cx, buf),
            Io::Socks4(stream) => Pin::new(stream).poll_read(cx, buf),
            Io::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Io {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Io::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            Io::Socks5(stream) => Pin::new(stream).poll_write(cx, buf),
            Io::Socks4(stream) => Pin::new(stream).poll_write(cx, buf),
            Io::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Io::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Io::Socks5(stream) => Pin::new(stream).poll_flush(cx),
            Io::Socks4(stream) => Pin::new(stream).poll_flush(cx),
            Io::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Io::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            Io::Socks5(stream) => Pin::new(stream).poll_shutdown(cx),
            Io::Socks4(stream) => Pin::new(stream).poll_shutdown(cx),
            Io::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

async fn tunnel(proxy: &Proxy, target: SocketAddr) -> Option<Io> {
    match proxy.scheme {
        Scheme::Socks5 => {
            let stream = tokio_socks::tcp::Socks5Stream::connect(proxy.addr, target)
                .await
                .ok()?;
            Some(Io::Socks5(stream))
        }
        Scheme::Socks4 => {
            let stream = tokio_socks::tcp::Socks4Stream::connect(proxy.addr, target)
                .await
                .ok()?;
            Some(Io::Socks4(stream))
        }
        Scheme::Http => {
            let mut stream = TcpStream::connect(proxy.addr).await.ok()?;
            http_connect(&mut stream, target).await?;
            Some(Io::Tcp(stream))
        }
        Scheme::Https => {
            let tcp = TcpStream::connect(proxy.addr).await.ok()?;
            let name = ServerName::try_from("localhost").ok()?.to_owned();
            let connector = tokio_rustls::TlsConnector::from(Arc::new(insecure_config()?));
            let mut tls = connector.connect(name, tcp).await.ok()?;
            http_connect(&mut tls, target).await?;
            Some(Io::Tls(tls))
        }
    }
}

async fn http_connect<S>(stream: &mut S, target: SocketAddr) -> Option<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Connection: keep-alive\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.ok()?;
    let header = read_header(stream).await?;
    if status_ok(&header) { Some(()) } else { None }
}

async fn doh_exchange<S>(stream: &mut S, addr: SocketAddr, query: &[u8]) -> Option<Message>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = format!(
        "POST /dns-query HTTP/1.1\r\nHost: {}\r\nContent-Type: application/dns-message\r\nAccept: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        addr.ip(),
        query.len()
    );
    stream.write_all(request.as_bytes()).await.ok()?;
    stream.write_all(query).await.ok()?;
    let header = read_header(stream).await?;
    if !status_ok(&header) {
        return None;
    }
    let body = read_body(stream, &header).await?;
    Message::from_bytes(&body).ok()
}

async fn dot_exchange<S>(stream: &mut S, query: &[u8]) -> Option<Message>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let len = u16::try_from(query.len()).ok()?;
    stream.write_all(&len.to_be_bytes()).await.ok()?;
    stream.write_all(query).await.ok()?;
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await.ok()?;
    let size = u16::from_be_bytes(len_buf) as usize;
    if size > 65_535 {
        return None;
    }
    let mut buf = vec![0u8; size];
    stream.read_exact(&mut buf).await.ok()?;
    Message::from_bytes(&buf).ok()
}

async fn read_header<S>(stream: &mut S) -> Option<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while buf.len() < 8192 {
        stream.read_exact(&mut byte).await.ok()?;
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return Some(buf);
        }
    }
    None
}

async fn read_body<S>(stream: &mut S, header: &[u8]) -> Option<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    if let Some(size) = content_length(header) {
        if size > 65_535 {
            return None;
        }
        let mut body = vec![0u8; size];
        stream.read_exact(&mut body).await.ok()?;
        return Some(body);
    }
    let mut body = Vec::new();
    stream.take(65_535).read_to_end(&mut body).await.ok()?;
    if body.is_empty() { None } else { Some(body) }
}

fn status_ok(header: &[u8]) -> bool {
    let line = header
        .split(|byte| *byte == b'\r' || *byte == b'\n')
        .next()
        .unwrap_or(b"");
    let Ok(text) = std::str::from_utf8(line) else {
        return false;
    };
    text.split_whitespace().nth(1) == Some("200")
}

fn content_length(header: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(header).ok()?.to_ascii_lowercase();
    for line in text.split("\r\n") {
        let Some(rest) = line.strip_prefix("content-length:") else {
            continue;
        };
        return rest.trim().parse().ok();
    }
    None
}

fn record_v4(record: &Record) -> Option<Ipv4Addr> {
    match record.data.ip_addr() {
        Some(IpAddr::V4(ip)) => Some(ip),
        _ => None,
    }
}

fn verified_config() -> Option<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Some(
        ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .ok()?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

fn insecure_config() -> Option<ClientConfig> {
    Some(
        ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .ok()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
            .with_no_client_auth(),
    )
}

#[derive(Debug)]
struct AcceptAnyCert;

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_lines_keep_scheme_preference_and_skip_junk() {
        let text = "\
http://1.2.3.4:8080
# comment
socks5://9.9.9.9:1080
not a proxy
https://3.3.3.3:443
socks4://4.4.4.4:1080
";
        let proxies = parse_proxy_list(text);
        let schemes: Vec<Scheme> = proxies.iter().map(|proxy| proxy.scheme).collect();
        assert_eq!(
            schemes,
            vec![Scheme::Socks5, Scheme::Socks4, Scheme::Http, Scheme::Https]
        );
        assert_eq!(proxies[0].addr, "9.9.9.9:1080".parse().unwrap());
    }

    #[test]
    fn country_index_keeps_directory_codes() {
        let text = r#"[
            {"name": "US", "path": "countries/US", "type": "dir"},
            {"name": "README", "path": "README.md", "type": "file"},
            {"name": "DE", "path": "countries/DE", "type": "dir"}
        ]"#;
        assert_eq!(
            parse_country_index(text),
            vec!["US".to_string(), "DE".to_string()]
        );
    }

    #[test]
    fn runtime_answer_rejects_a_poisoned_proxy() {
        assert!(usable_answer(&answer(
            ResponseCode::NXDomain,
            &[Ipv4Addr::new(1, 2, 3, 4)],
        )));
        assert!(!usable_answer(&answer(
            ResponseCode::NoError,
            &[Ipv4Addr::new(10, 10, 34, 34)],
        )));
        assert!(usable_answer(&answer(ResponseCode::NoError, &[])));
        assert!(!usable_answer(&answer(ResponseCode::ServFail, &[])));
        assert!(usable_answer(&answer(
            ResponseCode::NoError,
            &[
                Ipv4Addr::new(10, 10, 34, 34),
                Ipv4Addr::new(93, 184, 216, 34),
            ],
        )));
    }

    #[test]
    fn rewrite_moves_public_addresses_onto_the_queried_name() {
        let source = Name::from_ascii("cdn.example.net.").unwrap();
        let mut message = answer(ResponseCode::NoError, &[]);
        message.answers.push(Record::from_rdata(
            source.clone(),
            30,
            RData::A(A(Ipv4Addr::new(1, 2, 3, 4))),
        ));
        message.answers.push(Record::from_rdata(
            source,
            30,
            RData::A(A(Ipv4Addr::new(10, 10, 34, 34))),
        ));
        let qname = Name::from_ascii("www.youtube.com.").unwrap();
        let rewritten = rewrite_a(&message, &qname);
        assert_eq!(rewritten.answers.len(), 1);
        assert_eq!(rewritten.answers[0].name.to_string(), "www.youtube.com.");
        assert_eq!(
            record_v4(&rewritten.answers[0]),
            Some(Ipv4Addr::new(1, 2, 3, 4))
        );
    }

    #[test]
    fn snapshot_groups_proxies_by_country() {
        let text = "\
DE http://5.6.7.8:8080
US socks5://216.105.128.144:4145
US http://1.2.3.4:80
";
        let countries = group_proxies(text.lines().filter_map(parse_snapshot_line));
        assert_eq!(countries.len(), 2);
        assert_eq!(countries[0].code, "DE");
        assert_eq!(countries[1].code, "US");
        assert_eq!(countries[1].proxies[0].scheme, Scheme::Socks5);
        assert_eq!(countries[1].proxies[1].scheme, Scheme::Http);
    }

    fn answer(code: ResponseCode, ips: &[Ipv4Addr]) -> Message {
        let mut message = Message::new(1, MessageType::Response, OpCode::Query);
        message.metadata.response_code = code;
        let name = Name::from_ascii("example.com.").unwrap();
        for ip in ips {
            message
                .answers
                .push(Record::from_rdata(name.clone(), 60, RData::A(A(*ip))));
        }
        message
    }
}
