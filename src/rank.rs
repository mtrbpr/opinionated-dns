use std::net::Ipv4Addr;

/// Stored result of a connectivity probe. `None` means that check did not succeed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProbeScore {
    pub tcp80_ms: Option<u32>,
    pub tcp443_ms: Option<u32>,
    pub tls_ms: Option<u32>,
    pub tls_verified: bool,
    pub http_ms: Option<u32>,
}

impl ProbeScore {
    pub fn none() -> Self {
        Self {
            tcp80_ms: None,
            tcp443_ms: None,
            tls_ms: None,
            tls_verified: false,
            http_ms: None,
        }
    }
}

/// Lower sorts first. Tiers: verified TLS, ServerHello, HTTP, TCP 443, TCP 80, not yet probed, then every check failed.
pub fn rank_key(score: Option<ProbeScore>) -> (u8, u32) {
    let Some(score) = score else {
        return (5, u32::MAX);
    };
    if score.tls_verified {
        if let Some(ms) = score.tls_ms {
            return (0, ms);
        }
    }
    if let Some(ms) = score.tls_ms {
        return (1, ms);
    }
    if let Some(ms) = score.http_ms {
        return (2, ms);
    }
    if let Some(ms) = score.tcp443_ms {
        return (3, ms);
    }
    if let Some(ms) = score.tcp80_ms {
        return (4, ms);
    }
    (6, u32::MAX)
}

/// Order by connectivity and keep at most 10. Unprobed addresses, then fully failed ones, fill the tail.
pub fn select_addresses(
    ips: &[Ipv4Addr],
    score_of: impl Fn(Ipv4Addr) -> Option<ProbeScore>,
) -> Vec<Ipv4Addr> {
    let mut unique = Vec::new();
    for ip in ips {
        if !unique.contains(ip) {
            unique.push(*ip);
        }
    }
    unique.sort_by_key(|ip| rank_key(score_of(*ip)));
    unique.truncate(10);
    unique
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn ip(o: u8) -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, o)
    }

    #[test]
    fn verified_tls_beats_a_faster_server_hello() {
        let mut scores = HashMap::new();
        scores.insert(
            ip(1),
            ProbeScore {
                tls_ms: Some(50),
                tls_verified: true,
                ..ProbeScore::none()
            },
        );
        scores.insert(
            ip(2),
            ProbeScore {
                tls_ms: Some(10),
                tls_verified: false,
                ..ProbeScore::none()
            },
        );
        scores.insert(
            ip(3),
            ProbeScore {
                http_ms: Some(5),
                tcp80_ms: Some(1),
                ..ProbeScore::none()
            },
        );
        scores.insert(
            ip(4),
            ProbeScore {
                tcp443_ms: Some(1),
                ..ProbeScore::none()
            },
        );
        scores.insert(
            ip(5),
            ProbeScore {
                tcp80_ms: Some(1),
                ..ProbeScore::none()
            },
        );
        let ordered = select_addresses(&[ip(5), ip(4), ip(3), ip(2), ip(1), ip(6)], |addr| {
            scores.get(&addr).copied()
        });
        assert_eq!(ordered, vec![ip(1), ip(2), ip(3), ip(4), ip(5), ip(6)]);
    }

    #[test]
    fn faster_handshake_wins_inside_a_tier_and_the_list_is_capped() {
        let mut scores = HashMap::new();
        for n in 1..=12 {
            scores.insert(
                ip(n),
                ProbeScore {
                    tls_ms: Some(u32::from(n) * 10),
                    tls_verified: true,
                    ..ProbeScore::none()
                },
            );
        }
        let input: Vec<_> = (1..=12).rev().map(ip).collect();
        let ordered = select_addresses(&input, |addr| scores.get(&addr).copied());
        assert_eq!(ordered.len(), 10);
        assert_eq!(ordered[0], ip(1));
        assert_eq!(ordered[9], ip(10));
    }

    #[test]
    fn unreachable_addresses_fill_when_few_are_probed() {
        let mut scores = HashMap::new();
        scores.insert(
            ip(1),
            ProbeScore {
                tcp443_ms: Some(20),
                ..ProbeScore::none()
            },
        );
        scores.insert(ip(2), ProbeScore::none());
        let ordered = select_addresses(&[ip(2), ip(3), ip(1)], |addr| scores.get(&addr).copied());
        assert_eq!(ordered, vec![ip(1), ip(3), ip(2)]);
    }

    #[test]
    fn a_fully_failed_probe_stays_and_sorts_last() {
        let mut scores = HashMap::new();
        scores.insert(
            ip(1),
            ProbeScore {
                tcp80_ms: Some(30),
                ..ProbeScore::none()
            },
        );
        scores.insert(ip(3), ProbeScore::none());
        let ordered = select_addresses(&[ip(3), ip(2), ip(1)], |addr| scores.get(&addr).copied());
        assert_eq!(ordered, vec![ip(1), ip(2), ip(3)]);
    }
}
