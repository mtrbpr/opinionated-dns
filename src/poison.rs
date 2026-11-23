use std::net::Ipv4Addr;

/// Iranian filter sinks and addresses that can never be a useful public answer.
pub fn is_poison_v4(ip: Ipv4Addr) -> bool {
    let [a, b, _, _] = ip.octets();
    if a == 10 && b == 10 {
        return true;
    }
    if a == 0 || a == 127 {
        return true;
    }
    if (224..240).contains(&a) {
        return true;
    }
    ip.is_broadcast()
}

pub fn filter_v4(ips: impl IntoIterator<Item = Ipv4Addr>) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    for ip in ips {
        if !is_poison_v4(ip) && !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_filter_sink_and_keeps_other_ten_space() {
        assert!(is_poison_v4(Ipv4Addr::new(10, 10, 34, 34)));
        assert!(is_poison_v4(Ipv4Addr::new(10, 10, 0, 1)));
        assert!(!is_poison_v4(Ipv4Addr::new(10, 11, 0, 1)));
        assert!(!is_poison_v4(Ipv4Addr::new(10, 202, 10, 10)));
        assert!(is_poison_v4(Ipv4Addr::new(0, 0, 0, 1)));
        assert!(is_poison_v4(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_poison_v4(Ipv4Addr::new(224, 0, 0, 1)));
        assert!(is_poison_v4(Ipv4Addr::new(255, 255, 255, 255)));
        assert!(!is_poison_v4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_poison_v4(Ipv4Addr::new(8, 8, 8, 8)));
    }
}
