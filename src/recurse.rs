use std::net::{IpAddr, Ipv4Addr};

use hickory_proto::rr::Name;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::recursor::{DnssecPolicy, Recursor, RecursorOptions};

use crate::lists::IRNIC;
use crate::poison::is_poison_v4;

const ROOTS: [Ipv4Addr; 13] = [
    Ipv4Addr::new(198, 41, 0, 4),
    Ipv4Addr::new(170, 247, 170, 2),
    Ipv4Addr::new(192, 33, 4, 12),
    Ipv4Addr::new(199, 7, 91, 13),
    Ipv4Addr::new(192, 203, 230, 10),
    Ipv4Addr::new(192, 5, 5, 241),
    Ipv4Addr::new(192, 112, 36, 4),
    Ipv4Addr::new(198, 97, 190, 53),
    Ipv4Addr::new(192, 36, 148, 17),
    Ipv4Addr::new(192, 58, 128, 30),
    Ipv4Addr::new(193, 0, 14, 129),
    Ipv4Addr::new(199, 7, 83, 42),
    Ipv4Addr::new(202, 12, 27, 33),
];

pub struct Recursors {
    roots: Recursor<TokioRuntimeProvider>,
    ir: Recursor<TokioRuntimeProvider>,
}

impl Recursors {
    pub fn open() -> Self {
        let provider = TokioRuntimeProvider::new();
        let options = options();
        Self {
            roots: Recursor::new(
                &root_addresses(),
                DnssecPolicy::SecurityUnaware,
                None,
                options.clone(),
                provider.clone(),
            )
            .expect("root recursor"),
            ir: Recursor::new(
                &irnic_addresses(),
                DnssecPolicy::SecurityUnaware,
                None,
                options,
                provider,
            )
            .expect("irnic recursor"),
        }
    }

    pub fn for_name(&self, name: &Name) -> &Recursor<TokioRuntimeProvider> {
        if under_ir(name) {
            &self.ir
        } else {
            &self.roots
        }
    }
}

pub fn under_ir(name: &Name) -> bool {
    Name::from_ascii("ir.").expect("ir").zone_of(name)
}

pub fn root_addresses() -> Vec<IpAddr> {
    ROOTS.into_iter().map(IpAddr::V4).collect()
}

pub fn irnic_addresses() -> Vec<IpAddr> {
    IRNIC
        .iter()
        .filter_map(|ip| ip.parse::<Ipv4Addr>().ok())
        .map(IpAddr::V4)
        .collect()
}

pub fn addresses_for(name: &Name) -> Vec<IpAddr> {
    if under_ir(name) {
        irnic_addresses()
    } else {
        root_addresses()
    }
}

fn options() -> RecursorOptions {
    RecursorOptions {
        edns_payload_len: 1232,
        ..RecursorOptions::default()
    }
}

pub fn is_public_v4(ip: Ipv4Addr) -> bool {
    !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_broadcast()
        && !is_poison_v4(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ir_names_start_at_irnic_and_other_names_start_at_the_roots() {
        let www = Name::from_ascii("www.example.ir.").unwrap();
        let apex = Name::from_ascii("ir.").unwrap();
        let other = Name::from_ascii("example.com.").unwrap();
        assert_eq!(addresses_for(&www), irnic_addresses());
        assert_eq!(addresses_for(&apex), irnic_addresses());
        assert_eq!(addresses_for(&other), root_addresses());
        assert!(!under_ir(&other));
    }

    #[test]
    fn root_sets_are_public_addresses() {
        let roots = root_addresses();
        let irnic = irnic_addresses();
        assert_eq!(roots.len(), 13);
        assert!(!irnic.is_empty());
        for ip in roots.into_iter().chain(irnic) {
            let IpAddr::V4(ip) = ip else {
                panic!("expected ipv4");
            };
            assert!(is_public_v4(ip), "{ip}");
        }
    }

    #[test]
    fn recursors_build_without_a_network() {
        let _ = Recursors::open();
    }
}
