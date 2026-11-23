use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;

use ipnet::Ipv4Net;

use crate::poison::{filter_v4, is_poison_v4};

pub const IRANIAN_RESOLVERS: &[&str] = &[
    "178.22.122.100",
    "185.51.200.2",
    "78.157.42.100",
    "78.157.42.101",
    "185.55.226.26",
    "185.55.225.25",
    "94.103.125.157",
    "94.103.125.158",
    "181.41.194.177",
    "181.41.194.186",
    "10.202.10.202",
    "10.202.10.102",
    "10.202.10.10",
    "10.202.10.11",
    "85.15.1.14",
    "85.15.1.15",
    "5.202.100.100",
    "5.202.100.101",
    "91.99.101.12",
    "217.218.155.155",
    "217.218.127.127",
    "2.189.44.44",
];

pub const IRNIC: &[&str] = &[
    "193.189.123.2",
    "193.189.122.83",
    "194.225.70.83",
    "45.93.171.206",
];

#[derive(Clone, Debug, Default)]
pub struct Lists {
    pub resolvers: Vec<SocketAddr>,
    pub discovered: Vec<SocketAddr>,
    pub ir_prefixes: Vec<Ipv4Net>,
    pub cf_prefixes: Vec<Ipv4Net>,
    pub senpai: Vec<Ipv4Addr>,
}

impl Lists {
    pub fn vendored() -> Self {
        let mut lists = Self::default();
        lists.resolvers = IRANIAN_RESOLVERS
            .iter()
            .filter_map(|ip| ip.parse::<IpAddr>().ok())
            .map(|ip| SocketAddr::new(ip, 53))
            .collect();
        lists
    }
}

pub fn parse_prefixes(text: &str) -> Vec<Ipv4Net> {
    text.lines()
        .filter_map(|line| {
            let line = line.split('#').next()?.trim();
            if line.is_empty() {
                None
            } else {
                line.parse().ok()
            }
        })
        .collect()
}

pub fn parse_ir_csv(text: &str) -> Vec<IpAddr> {
    text.lines()
        .skip(1)
        .filter_map(|line| line.split(',').next()?.trim().parse().ok())
        .collect()
}

pub fn parse_ipv4s(text: &str) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    let mut current = String::new();
    for ch in text.chars().chain(std::iter::once('\n')) {
        if ch.is_ascii_digit() || ch == '.' {
            current.push(ch);
            continue;
        }
        if let Ok(ip) = current.parse::<Ipv4Addr>() {
            if !is_poison_v4(ip) && !out.contains(&ip) {
                out.push(ip);
            }
        }
        current.clear();
    }
    filter_v4(out)
}

pub fn is_cloudflare_ns(name: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    name == "ns.cloudflare.com" || name.ends_with(".ns.cloudflare.com")
}

pub fn is_cloudflare_cname(name: &str) -> bool {
    name.to_ascii_lowercase().contains("cloudflare")
}

pub fn ip_in_prefixes(ip: Ipv4Addr, prefixes: &[Ipv4Net]) -> bool {
    prefixes.iter().any(|prefix| prefix.contains(&ip))
}

pub fn is_cloudflare(
    nameservers: &[String],
    cnames: &[String],
    addresses: &[Ipv4Addr],
    prefixes: &[Ipv4Net],
) -> bool {
    nameservers.iter().any(|name| is_cloudflare_ns(name))
        || cnames.iter().any(|name| is_cloudflare_cname(name))
        || addresses.iter().any(|ip| ip_in_prefixes(*ip, prefixes))
}

pub fn in_iran(ip: Ipv4Addr, prefixes: &[Ipv4Net]) -> bool {
    IRNIC
        .iter()
        .any(|item| item.parse::<Ipv4Addr>().ok() == Some(ip))
        || ip_in_prefixes(ip, prefixes)
}

const EMBEDDED_IR_ZONE: &str = include_str!("../static/ir.zone");
const EMBEDDED_CLOUDFLARE_PREFIXES: &str = include_str!("../static/cloudflare-ipv4.txt");
const EMBEDDED_SENPAI: &str = include_str!("../static/cloudflare-ips.txt");
const EMBEDDED_IRANIAN_RESOLVERS: &str = include_str!("../static/iranian-resolvers.txt");
const EMBEDDED_PUBLIC_RESOLVERS: &str = include_str!("../static/public-resolvers.md");
const EMBEDDED_RELAYS: &str = include_str!("../static/relays.md");

pub fn load_snapshot(data_dir: &Path) -> Lists {
    let mut lists = Lists::vendored();
    lists.ir_prefixes = parse_prefixes(&stored_or_embedded(data_dir, "ir.zone", EMBEDDED_IR_ZONE));
    lists.cf_prefixes = parse_prefixes(&stored_or_embedded(
        data_dir,
        "cloudflare-ipv4.txt",
        EMBEDDED_CLOUDFLARE_PREFIXES,
    ));
    lists.senpai = parse_ipv4s(&stored_or_embedded(
        data_dir,
        "cloudflare-ips.txt",
        EMBEDDED_SENPAI,
    ));
    let mut extra = parse_resolver_lines(&stored_or_embedded(
        data_dir,
        "iranian-resolvers.txt",
        EMBEDDED_IRANIAN_RESOLVERS,
    ));
    for resolver in lists.resolvers {
        if !extra.contains(&resolver) {
            extra.push(resolver);
        }
    }
    lists.resolvers = extra;
    lists.discovered = load_discovered(data_dir);
    lists
}

fn stored_or_embedded(dir: &Path, name: &str, embedded: &str) -> String {
    std::fs::read_to_string(dir.join(name))
        .ok()
        .filter(|text| !text.trim().is_empty())
        .unwrap_or_else(|| embedded.to_string())
}

pub const DNSCRYPT_MINISIGN_KEY: &str = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";

pub const PUBLIC_RESOLVER_URLS: &[&str] = &[
    "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md",
    "https://download.dnscrypt.info/resolvers-list/v3/public-resolvers.md",
];

pub const RELAY_URLS: &[&str] = &[
    "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/relays.md",
    "https://download.dnscrypt.info/resolvers-list/v3/relays.md",
];

pub fn load_discovered(data_dir: &Path) -> Vec<SocketAddr> {
    let resolvers = stored_or_embedded(data_dir, "public-resolvers.md", EMBEDDED_PUBLIC_RESOLVERS);
    let relays = stored_or_embedded(data_dir, "relays.md", EMBEDDED_RELAYS);
    merge_discovered(&parse_stamp_list(&resolvers), &parse_stamp_list(&relays))
}

pub fn signature_ok(message: &[u8], signature_text: &str) -> bool {
    let Ok(key) = minisign_verify::PublicKey::from_base64(DNSCRYPT_MINISIGN_KEY) else {
        return false;
    };
    let Ok(signature) = minisign_verify::Signature::decode(signature_text) else {
        return false;
    };
    // DNSCrypt publishes legacy Ed25519 signatures (algorithm Ed), not the
    // prehashed variant. `allow_legacy` still checks this key id.
    key.verify(message, &signature, true).is_ok()
}

pub fn parse_stamp_list(text: &str) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(stamp) = line.trim().strip_prefix("sdns://") else {
            continue;
        };
        let Some(ip) = stamp_ip(stamp) else {
            continue;
        };
        if let IpAddr::V4(ip) = ip {
            if is_poison_v4(ip) {
                continue;
            }
        }
        let addr = SocketAddr::new(ip, 53);
        if !out.contains(&addr) {
            out.push(addr);
        }
    }
    out
}

pub fn merge_discovered(first: &[SocketAddr], second: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut out = first.to_vec();
    for addr in second {
        if !out.contains(addr) {
            out.push(*addr);
        }
    }
    out
}

fn stamp_ip(stamp: &str) -> Option<IpAddr> {
    let bytes = decode_stamp(stamp)?;
    let proto = *bytes.first()?;
    let addr_at = match proto {
        0x00 | 0x01 | 0x02 | 0x03 | 0x04 | 0x05 => 9,
        0x81 | 0x85 => 1,
        _ => return None,
    };
    let (addr, _) = read_lp(&bytes, addr_at)?;
    ip_from_addr(&addr)
}

fn decode_stamp(stamp: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let stamp = stamp.trim();
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(stamp)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(stamp))
        .ok()
}

fn read_lp(bytes: &[u8], at: usize) -> Option<(String, usize)> {
    let len = *bytes.get(at)? as usize;
    let start = at + 1;
    let end = start + len;
    let text = std::str::from_utf8(bytes.get(start..end)?).ok()?;
    Some((text.to_string(), end))
}

fn ip_from_addr(addr: &str) -> Option<IpAddr> {
    if addr.is_empty() {
        return None;
    }
    if let Ok(ip) = addr.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(socket) = addr.parse::<SocketAddr>() {
        return Some(socket.ip());
    }
    None
}

pub fn parse_resolver_lines(text: &str) -> Vec<SocketAddr> {
    text.lines()
        .filter_map(|line| {
            let line = line.split('#').next()?.trim();
            if line.is_empty() {
                return None;
            }
            if let Ok(addr) = line.parse::<SocketAddr>() {
                return Some(addr);
            }
            line.parse::<IpAddr>()
                .ok()
                .map(|ip| SocketAddr::new(ip, 53))
        })
        .collect()
}

pub fn write_resolvers(path: &Path, resolvers: &[SocketAddr]) {
    let body = resolvers
        .iter()
        .map(|addr| addr.ip().to_string())
        .collect::<Vec<_>>()
        .join("\n");
    let _ = std::fs::write(path, body + "\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudflare_detection_uses_ns_cname_and_prefixes() {
        let prefixes = parse_prefixes("104.16.0.0/13\n172.64.0.0/13\n");
        assert!(is_cloudflare_ns("ada.ns.cloudflare.com."));
        assert!(!is_cloudflare_ns("ns1.example.com."));
        assert!(is_cloudflare(
            &["ada.ns.cloudflare.com.".into()],
            &[],
            &[],
            &prefixes
        ));
        assert!(is_cloudflare(
            &[],
            &["example.com.cdn.cloudflare.net.".into()],
            &[],
            &prefixes
        ));
        assert!(is_cloudflare(
            &[],
            &[],
            &[Ipv4Addr::new(104, 16, 1, 2)],
            &prefixes
        ));
        assert!(!is_cloudflare(
            &["ns1.example.ir.".into()],
            &["www.example.ir.".into()],
            &[Ipv4Addr::new(185, 166, 104, 1)],
            &prefixes
        ));
    }

    #[test]
    fn senpai_output_and_poison_are_parsed() {
        let ips = parse_ipv4s("working 104.16.1.2:443\n10.10.34.34\n# comment\n172.64.10.8\n");
        assert_eq!(
            ips,
            vec![Ipv4Addr::new(104, 16, 1, 2), Ipv4Addr::new(172, 64, 10, 8)]
        );
    }

    #[test]
    fn iranian_csv_skips_the_header() {
        let ips = parse_ir_csv("ip_address,name\n1.2.3.4,ns.example.\n2001:db8::1,v6.\n");
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], IpAddr::from(Ipv4Addr::new(1, 2, 3, 4)));
    }

    fn stamp_line(proto: u8, with_props: bool, addr: &str) -> String {
        use base64::Engine;
        let mut raw = vec![proto];
        if with_props {
            raw.extend_from_slice(&[0; 8]);
        }
        raw.push(u8::try_from(addr.len()).unwrap());
        raw.extend(addr.as_bytes());
        format!(
            "sdns://{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
        )
    }

    #[test]
    fn stamps_become_port_53_and_duplicates_and_poison_are_dropped() {
        let resolvers = format!(
            "## dnscrypt\n{}\n## empty doh\n{}\n## hostname\n{}\n## bare ip\n{}\n",
            stamp_line(0x01, true, "198.51.100.8:5443"),
            stamp_line(0x02, true, ""),
            stamp_line(0x02, true, "dns.example"),
            stamp_line(0x02, true, "1.1.1.1"),
        );
        let relays = format!(
            "{}\n{}\n{}\n",
            stamp_line(0x81, false, "198.51.100.9:443"),
            stamp_line(0x81, false, "10.10.34.34:443"),
            stamp_line(0x81, false, "198.51.100.8:9999"),
        );
        let parsed = parse_stamp_list(&resolvers);
        assert_eq!(
            parsed,
            vec![
                SocketAddr::from(([198, 51, 100, 8], 53)),
                SocketAddr::from(([1, 1, 1, 1], 53)),
            ]
        );
        let merged = merge_discovered(&parsed, &parse_stamp_list(&relays));
        assert_eq!(
            merged,
            vec![
                SocketAddr::from(([198, 51, 100, 8], 53)),
                SocketAddr::from(([1, 1, 1, 1], 53)),
                SocketAddr::from(([198, 51, 100, 9], 53)),
            ]
        );
    }

    #[test]
    fn embedded_lists_answer_before_any_download() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("static");
        let resolvers = std::fs::read(root.join("public-resolvers.md")).unwrap();
        let resolver_sig =
            std::fs::read_to_string(root.join("public-resolvers.md.minisig")).unwrap();
        let relays = std::fs::read(root.join("relays.md")).unwrap();
        let relay_sig = std::fs::read_to_string(root.join("relays.md.minisig")).unwrap();
        assert!(signature_ok(&resolvers, &resolver_sig));
        assert!(signature_ok(&relays, &relay_sig));

        let empty =
            std::env::temp_dir().join(format!("opinionated-dns-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&empty);
        std::fs::create_dir_all(&empty).unwrap();
        let lists = load_snapshot(&empty);
        let _ = std::fs::remove_dir_all(&empty);
        assert!(!lists.ir_prefixes.is_empty());
        assert!(!lists.cf_prefixes.is_empty());
        assert!(!lists.senpai.is_empty());
        assert!(lists.resolvers.len() >= IRANIAN_RESOLVERS.len());
        assert!(lists.discovered.len() > 100);
    }

    #[test]
    fn bad_minisign_blob_is_rejected() {
        assert!(!signature_ok(b"list", "not a signature"));
        assert!(!signature_ok(
            b"list",
            "untrusted comment: x\nAAAA\ntrusted comment: y\nBBBB\n"
        ));
    }
}
