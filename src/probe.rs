use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::rank::ProbeScore;

pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub struct ProbeOutcome {
    pub score: ProbeScore,
    pub sans: Vec<String>,
}

pub async fn probe(ip: IpAddr, sni: &str, limit: Duration) -> ProbeOutcome {
    let (tcp80, tcp443, tls, http) = tokio::join!(
        tcp_ms(ip, 80, limit),
        tcp_ms(ip, 443, limit),
        tls_probe(ip, sni, limit),
        http_ms(ip, sni, limit),
    );
    ProbeOutcome {
        score: ProbeScore {
            tcp80_ms: tcp80,
            tcp443_ms: tcp443,
            tls_ms: tls.0,
            tls_verified: tls.1,
            http_ms: http,
        },
        sans: tls.2,
    }
}

async fn tcp_ms(ip: IpAddr, port: u16, limit: Duration) -> Option<u32> {
    let started = Instant::now();
    timeout(limit, TcpStream::connect((ip, port)))
        .await
        .ok()?
        .ok()?;
    Some(ms(started))
}

async fn http_ms(ip: IpAddr, host: &str, limit: Duration) -> Option<u32> {
    let started = Instant::now();
    let mut stream = timeout(limit, TcpStream::connect((ip, 80)))
        .await
        .ok()?
        .ok()?;
    let host = host.trim_end_matches('.');
    let request = format!("GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    timeout(limit, stream.write_all(request.as_bytes()))
        .await
        .ok()?
        .ok()?;
    let mut buf = [0u8; 32];
    let read = timeout(limit, stream.read(&mut buf)).await.ok()?.ok()?;
    if read == 0 { None } else { Some(ms(started)) }
}

async fn tls_probe(ip: IpAddr, sni: &str, limit: Duration) -> (Option<u32>, bool, Vec<String>) {
    let (hello, verified) = tokio::join!(
        server_hello_ms(ip, sni, limit),
        verified_tls(ip, sni, limit)
    );
    let ms = hello.or(verified.0);
    (ms, verified.0.is_some(), verified.1)
}

async fn server_hello_ms(ip: IpAddr, sni: &str, limit: Duration) -> Option<u32> {
    let started = Instant::now();
    let mut stream = timeout(limit, TcpStream::connect((ip, 443)))
        .await
        .ok()?
        .ok()?;
    let hello = client_hello(sni.trim_end_matches('.'));
    timeout(limit, stream.write_all(&hello)).await.ok()?.ok()?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match timeout(remaining, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&chunk[..n]);
                if contains_server_hello(&buf) {
                    return Some(ms(started));
                }
            }
        }
    }
    None
}

async fn verified_tls(ip: IpAddr, sni: &str, limit: Duration) -> (Option<u32>, Vec<String>) {
    let sni = sni.trim_end_matches('.');
    let Some(server_name) = ServerName::try_from(sni).ok().map(|name| name.to_owned()) else {
        return (None, Vec::new());
    };
    let started = Instant::now();
    let Some(config) = verified_config() else {
        return (None, Vec::new());
    };
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let Ok(Ok(stream)) = timeout(limit, TcpStream::connect((ip, 443))).await else {
        return (None, Vec::new());
    };
    let Ok(Ok(tls)) = timeout(limit, connector.connect(server_name, stream)).await else {
        return (None, Vec::new());
    };
    let sans = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|cert| crate::siblings::concrete_dns_names(cert.as_ref()))
        .unwrap_or_default();
    (Some(ms(started)), sans)
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

fn ms(started: Instant) -> u32 {
    u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX)
}

pub fn client_hello(sni: &str) -> Vec<u8> {
    let sni = if sni.is_empty() { "localhost" } else { sni };
    let mut extensions = Vec::new();
    extensions.extend(ext_sni(sni.as_bytes()));
    extensions.extend(ext_u16_list(0x002b, &[0x0304, 0x0303]));
    extensions.extend(ext_u16_list(
        0x000d,
        &[0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501],
    ));
    extensions.extend(ext_u16_list(0x000a, &[0x001d, 0x0017]));
    extensions.extend(ext_key_share());

    let mut hello = Vec::new();
    hello.extend_from_slice(&[0x03, 0x03]);
    hello.extend_from_slice(&[0x11; 32]);
    hello.push(0);
    let ciphers: &[u8] = &[0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2f, 0xc0, 0x30];
    hello.extend_from_slice(&(ciphers.len() as u16).to_be_bytes());
    hello.extend_from_slice(ciphers);
    hello.extend_from_slice(&[0x01, 0x00]);
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(0x01);
    handshake.extend_from_slice(&u24(hello.len()));
    handshake.extend_from_slice(&hello);

    let mut record = Vec::new();
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn ext_sni(host: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    let entry_len = 1 + 2 + host.len();
    body.extend_from_slice(&(entry_len as u16).to_be_bytes());
    body.push(0);
    body.extend_from_slice(&(host.len() as u16).to_be_bytes());
    body.extend_from_slice(host);
    ext(0, &body)
}

fn ext_u16_list(kind: u16, values: &[u16]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&((values.len() * 2) as u16).to_be_bytes());
    for value in values {
        body.extend_from_slice(&value.to_be_bytes());
    }
    ext(kind, &body)
}

fn ext_key_share() -> Vec<u8> {
    let key = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    let mut share = Vec::new();
    share.extend_from_slice(&0x001du16.to_be_bytes());
    share.extend_from_slice(&(key.len() as u16).to_be_bytes());
    share.extend_from_slice(&key);
    let mut body = Vec::new();
    body.extend_from_slice(&(share.len() as u16).to_be_bytes());
    body.extend_from_slice(&share);
    ext(0x0033, &body)
}

fn ext(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn u24(len: usize) -> [u8; 3] {
    let len = len as u32;
    [(len >> 16) as u8, (len >> 8) as u8, len as u8]
}

pub fn contains_server_hello(buf: &[u8]) -> bool {
    let mut offset = 0;
    while offset + 5 <= buf.len() {
        let kind = buf[offset];
        let len = u16::from_be_bytes([buf[offset + 3], buf[offset + 4]]) as usize;
        let start = offset + 5;
        let end = start + len;
        if end > buf.len() {
            return false;
        }
        if kind == 0x16 && len > 0 && buf[start] == 0x02 {
            return true;
        }
        offset = end;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_is_a_handshake_record_carrying_sni() {
        let hello = client_hello("example.com");
        assert_eq!(hello[0], 0x16);
        assert!(hello.windows(11).any(|window| window == b"example.com"));
        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(hello.len(), 5 + record_len);
        assert_eq!(hello[5], 0x01);
    }

    #[test]
    fn server_hello_record_is_recognized() {
        let mut buf = vec![0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00];
        assert!(contains_server_hello(&buf));
        buf[5] = 0x01;
        assert!(!contains_server_hello(&buf));
    }
}
