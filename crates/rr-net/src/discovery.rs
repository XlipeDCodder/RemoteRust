//! Local interface discovery and VPN classification (blueprint v2 §5.2).
//!
//! Classification is a reachability hint, never a security decision:
//! every path is treated as hostile and peers are authenticated by key.

use std::collections::BTreeSet;
use std::net::IpAddr;

use ipnet::IpNet;
use rr_proto::NetworkClass;

/// One local network interface, as RustRemote sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalInterface {
    /// OS identifier (an adapter GUID on Windows, `eth0` on Linux).
    pub name: String,
    /// Human-friendly name (`Ethernet`, `Tailscale`, `tailscale0`).
    pub label: String,
    /// Adapter description, when the OS provides one.
    pub description: Option<String>,
    /// Detected network class; `None` means ignored (virtual or unknown).
    pub class: Option<NetworkClass>,
    /// Whether the OS reports the interface as up.
    pub up: bool,
    /// Usable unicast addresses with their prefix (link-local excluded).
    pub addrs: Vec<IpNet>,
}

/// The inputs classification looks at, separated from `netdev` for tests.
#[derive(Debug, Clone, Copy, Default)]
pub struct InterfaceFacts<'a> {
    /// OS identifier.
    pub name: &'a str,
    /// Friendly name (Windows).
    pub friendly_name: Option<&'a str>,
    /// Adapter description (Windows).
    pub description: Option<&'a str>,
    /// Backed by physical hardware, per the OS and MAC vendor.
    pub physical: bool,
}

/// Name fragments of virtual adapters that are never used, compared in
/// lowercase. Checked after the VPN rules, so a VPN is never ignored.
const IGNORED: &[&str] = &[
    "vethernet",
    "hyper-v",
    "docker",
    "virbr",
    "veth",
    "vmware",
    "virtualbox",
    "vboxnet",
    "wsl",
    "zerotier",
    "wireguard",
    "hamachi",
    "openvpn",
    "tap-windows",
    "npcap",
    "bluetooth",
    "loopback",
    "teredo",
    "isatap",
];

/// Applies the classification rules of blueprint v2 §5.2.
#[must_use]
pub fn classify(facts: &InterfaceFacts<'_>) -> Option<NetworkClass> {
    let texts: Vec<String> = [Some(facts.name), facts.friendly_name, facts.description]
        .into_iter()
        .flatten()
        .map(str::to_ascii_lowercase)
        .collect();
    let mentions = |needle: &str| texts.iter().any(|text| text.contains(needle));

    if mentions("tailscale") {
        Some(NetworkClass::Tailscale)
    } else if mentions("radmin vpn") {
        Some(NetworkClass::Radmin)
    } else if mentions("fortinet") || mentions("forticlient") || facts.name.starts_with("ppp") {
        // Linux FortiClient (legacy SSL-VPN) shows up as `ppp*`.
        Some(NetworkClass::FortiClient)
    } else if IGNORED.iter().any(|fragment| mentions(fragment)) {
        None
    } else if facts.physical {
        Some(NetworkClass::Lan)
    } else {
        None
    }
}

/// Whether a local address can host a listener or originate a path.
#[must_use]
pub fn is_usable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast())
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unicast_link_local())
        }
    }
}

/// Lists and classifies the local interfaces (loopback excluded).
/// Blocking: call it from `spawn_blocking` in async code.
#[must_use]
pub fn discover() -> Vec<LocalInterface> {
    netdev::get_interfaces()
        .into_iter()
        .filter(|iface| !iface.is_loopback())
        .map(|iface| {
            let class = classify(&InterfaceFacts {
                name: &iface.name,
                friendly_name: iface.friendly_name.as_deref(),
                description: iface.description.as_deref(),
                physical: iface.is_physical(),
            });
            let addrs = iface
                .ipv4
                .iter()
                .copied()
                .map(IpNet::V4)
                .chain(iface.ipv6.iter().copied().map(IpNet::V6))
                .filter(|net| is_usable(net.addr()))
                .collect();
            LocalInterface {
                label: iface
                    .friendly_name
                    .clone()
                    .unwrap_or_else(|| iface.name.clone()),
                up: iface.is_up(),
                name: iface.name,
                description: iface.description,
                class,
                addrs,
            }
        })
        .collect()
}

/// Classes with at least one interface that is up and has an address.
#[must_use]
pub fn active_classes(interfaces: &[LocalInterface]) -> BTreeSet<NetworkClass> {
    interfaces
        .iter()
        .filter(|iface| iface.up && !iface.addrs.is_empty())
        .filter_map(|iface| iface.class)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class_of(
        name: &str,
        friendly: Option<&str>,
        desc: Option<&str>,
        physical: bool,
    ) -> Option<NetworkClass> {
        classify(&InterfaceFacts {
            name,
            friendly_name: friendly,
            description: desc,
            physical,
        })
    }

    #[test]
    fn windows_adapters() {
        let guid = "{6E5C2A31-0000-0000-0000-000000000000}";
        assert_eq!(
            class_of(guid, Some("Tailscale"), Some("Tailscale Tunnel"), false),
            Some(NetworkClass::Tailscale)
        );
        assert_eq!(
            class_of(
                guid,
                Some("Radmin VPN"),
                Some("Famatech Radmin VPN Ethernet Adapter"),
                false
            ),
            Some(NetworkClass::Radmin)
        );
        assert_eq!(
            class_of(
                guid,
                Some("Ethernet 3"),
                Some("Fortinet SSL VPN Virtual Ethernet Adapter"),
                false
            ),
            Some(NetworkClass::FortiClient)
        );
        assert_eq!(
            class_of(
                guid,
                Some("Ethernet"),
                Some("Intel(R) Ethernet Connection I219-V"),
                true
            ),
            Some(NetworkClass::Lan)
        );
        assert_eq!(
            class_of(
                guid,
                Some("vEthernet (WSL)"),
                Some("Hyper-V Virtual Ethernet Adapter"),
                true
            ),
            None
        );
        assert_eq!(
            class_of(
                guid,
                Some("Ethernet 2"),
                Some("VirtualBox Host-Only Ethernet Adapter"),
                false
            ),
            None
        );
    }

    #[test]
    fn linux_interfaces() {
        assert_eq!(
            class_of("tailscale0", None, None, false),
            Some(NetworkClass::Tailscale)
        );
        assert_eq!(
            class_of("ppp0", None, None, false),
            Some(NetworkClass::FortiClient)
        );
        assert_eq!(
            class_of("enp3s0", None, None, true),
            Some(NetworkClass::Lan)
        );
        assert_eq!(class_of("docker0", None, None, false), None);
        assert_eq!(class_of("virbr0", None, None, false), None);
        assert_eq!(class_of("veth12ab", None, None, false), None);
        assert_eq!(class_of("wg0", None, None, false), None);
    }

    #[test]
    fn vpn_rules_win_over_ignore_rules() {
        // A Tailscale adapter whose description mentions WireGuard.
        assert_eq!(
            class_of("x", Some("Tailscale"), Some("WireGuard Tunnel"), false),
            Some(NetworkClass::Tailscale)
        );
    }

    #[test]
    fn usable_addresses() {
        for ok in [
            "100.101.102.103",
            "26.1.2.3",
            "192.168.1.10",
            "fd7a:115c:a1e0::1",
            "2001:db8::1",
        ] {
            assert!(is_usable(ok.parse().unwrap()), "{ok}");
        }
        for bad in [
            "127.0.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "fe80::1",
            "::",
            "ff02::1",
        ] {
            assert!(!is_usable(bad.parse().unwrap()), "{bad}");
        }
    }

    #[test]
    fn active_classes_need_up_and_addresses() {
        let iface = |class, up, addrs: &[&str]| LocalInterface {
            name: "x".into(),
            label: "x".into(),
            description: None,
            class: Some(class),
            up,
            addrs: addrs.iter().map(|a| a.parse().unwrap()).collect(),
        };
        let classes = active_classes(&[
            iface(NetworkClass::Tailscale, true, &["100.64.1.2/32"]),
            iface(NetworkClass::Radmin, false, &["26.1.2.3/8"]),
            iface(NetworkClass::Lan, true, &[]),
        ]);
        assert_eq!(
            classes.into_iter().collect::<Vec<_>>(),
            [NetworkClass::Tailscale]
        );
    }

    #[test]
    fn discover_does_not_panic() {
        // Smoke test against the real machine; contents vary per host.
        for iface in discover() {
            assert!(iface.addrs.iter().all(|net| is_usable(net.addr())));
        }
    }
}
