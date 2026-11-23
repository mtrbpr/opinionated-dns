use std::sync::LazyLock;

use hickory_proto::rr::Name;
use publicsuffix::{List, Psl};

pub const MAX_RELATED: usize = 16;

const EARLY_LABELS: &[&str] = &["www", "mail"];

const LABELS: &[&str] = &[
    "smtp",
    "imap",
    "pop",
    "autodiscover",
    "login",
    "accounts",
    "account",
    "api",
    "cdn",
    "static",
    "app",
    "m",
    "portal",
    "edge",
    "origin",
];

static SUFFIXES: LazyLock<List> = LazyLock::new(|| {
    include_str!("public_suffix_list.dat")
        .parse()
        .expect("public suffix list")
});

pub fn registrable(name: &Name) -> Option<String> {
    registrable_str(&name.to_string())
}

pub fn registrable_str(name: &str) -> Option<String> {
    let host = clean_host(name)?;
    let domain = SUFFIXES.domain(host.as_bytes())?;
    let text = std::str::from_utf8(domain.trim().as_bytes()).ok()?;
    Some(text.to_ascii_lowercase())
}

/// Names whose addresses are candidates for `qname`. The query name itself is excluded.
pub fn related_names(qname: &Name, known: &[String]) -> Vec<Name> {
    let Some(zone) = registrable(qname) else {
        return Vec::new();
    };
    let query = clean_host(&qname.to_string());
    let mut same = Vec::new();
    let mut other = Vec::new();
    let mut push = |host: &str, bucket_same: bool| {
        let Some(host) = clean_host(host) else {
            return;
        };
        if query.as_ref() == Some(&host) {
            return;
        }
        let list = if bucket_same { &mut same } else { &mut other };
        if list.iter().any(|existing| existing == &host) {
            return;
        }
        list.push(host);
    };

    push(&zone, true);
    for label in EARLY_LABELS {
        push(&format!("{label}.{zone}"), true);
    }
    for name in known {
        let same_zone = registrable_str(name).as_deref() == Some(zone.as_str());
        push(name, same_zone);
    }
    for label in LABELS {
        push(&format!("{label}.{zone}"), true);
    }

    same.append(&mut other);
    same.truncate(MAX_RELATED);
    same.into_iter()
        .filter_map(|host| parse_name(&host))
        .collect()
}

pub fn concrete_dns_names(der: &[u8]) -> Vec<String> {
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(der) else {
        return Vec::new();
    };
    let Ok(Some(san)) = cert.subject_alternative_name() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for name in &san.value.general_names {
        if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
            if let Some(host) = clean_host(dns) {
                if !out.contains(&host) {
                    out.push(host);
                }
            }
        }
    }
    out
}

pub fn clean_host(name: &str) -> Option<String> {
    let host = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || host.contains('*') || host.contains(' ') || host.contains('/') {
        return None;
    }
    Some(host)
}

fn parse_name(host: &str) -> Option<Name> {
    let mut name = Name::from_ascii(host).ok()?;
    name.set_fqdn(true);
    Some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> Name {
        parse_name(text).unwrap()
    }

    fn hosts(names: &[Name]) -> Vec<String> {
        names
            .iter()
            .map(|name| clean_host(&name.to_string()).unwrap())
            .collect()
    }

    #[test]
    fn mail_google_is_related_to_google_and_the_query_is_excluded() {
        let related = related_names(&name("google.com"), &[]);
        let hosts = hosts(&related);
        assert!(hosts.contains(&"mail.google.com".to_string()));
        assert!(hosts.contains(&"www.google.com".to_string()));
        assert!(!hosts.contains(&"google.com".to_string()));
        assert!(related.len() <= MAX_RELATED);
    }

    #[test]
    fn registrable_domain_keeps_the_public_suffix() {
        assert_eq!(
            registrable(&name("www.example.co.uk")).as_deref(),
            Some("example.co.uk")
        );
        assert_ne!(
            registrable(&name("www.example.co.uk")).as_deref(),
            Some("co.uk")
        );
        assert_eq!(
            registrable(&name("mail.google.com")).as_deref(),
            Some("google.com")
        );
    }

    #[test]
    fn wildcard_sans_are_ignored_and_concrete_names_are_kept() {
        let related = related_names(
            &name("google.com"),
            &[
                "*.google.com".into(),
                "mail.google.com".into(),
                "photos.google.com".into(),
                "youtube.com".into(),
            ],
        );
        let hosts = hosts(&related);
        assert!(hosts.contains(&"mail.google.com".to_string()));
        assert!(hosts.contains(&"photos.google.com".to_string()));
        assert!(!hosts.iter().any(|host| host.contains('*')));
        let photos = hosts.iter().position(|host| host == "photos.google.com");
        let youtube = hosts.iter().position(|host| host == "youtube.com");
        if let (Some(photos), Some(youtube)) = (photos, youtube) {
            assert!(photos < youtube);
        }
        assert!(related.len() <= MAX_RELATED);
    }

    #[test]
    fn related_names_stop_at_sixteen() {
        let extra: Vec<String> = (0..40).map(|n| format!("svc{n}.google.com")).collect();
        let related = related_names(&name("google.com"), &extra);
        assert_eq!(related.len(), MAX_RELATED);
    }

    #[test]
    fn garbage_certificate_has_no_names() {
        assert!(concrete_dns_names(b"not a certificate").is_empty());
    }
}
