//! Agent listeners: one QUIC endpoint per enabled interface address, each
//! with its own source allowlist (blueprint v2 §5.3).

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use rr_config::{AgentConfig, NetworkPolicy};
use rr_proto::{CandidateAddr, NetworkClass};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::agent::{Agent, SourceFilter};
use crate::discovery::{self, LocalInterface};

/// Tailscale's IPv4 range (CGNAT space it assigns from).
pub const TAILSCALE_V4: IpNet = IpNet::V4(Ipv4Net::new_assert(Ipv4Addr::new(100, 64, 0, 0), 10));

/// Tailscale's IPv6 ULA range.
pub const TAILSCALE_V6: IpNet = IpNet::V6(Ipv6Net::new_assert(
    Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0),
    48,
));

/// How often interfaces are re-scanned for VPNs coming up or down.
pub const RESCAN_INTERVAL: Duration = Duration::from_secs(3);

/// One listener to open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenTarget {
    /// Network the address belongs to.
    pub class: NetworkClass,
    /// Interface label, for display.
    pub interface: String,
    /// Local socket address to bind.
    pub addr: SocketAddr,
    /// Source networks allowed to reach it.
    pub allowed: Vec<IpNet>,
}

/// An interface or address that was deliberately not listened on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// Interface label or address.
    pub what: String,
    /// Why.
    pub reason: &'static str,
}

/// The listeners the configuration asks for on the current interfaces.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListenPlan {
    /// Listeners to open.
    pub targets: Vec<ListenTarget>,
    /// Classified interfaces left out, with the reason.
    pub skipped: Vec<Skipped>,
}

/// Computes the listeners for `interfaces` under `config`.
///
/// - Only classes with `listen` and `attended` enabled get listeners (M1
///   has attended sessions only).
/// - Allowlists come from `allowed_sources` or, if empty, default to the
///   Tailscale ranges or the interface's own subnet.
/// - A point-to-point address (`/32`, `/128`) has no meaningful subnet and
///   is skipped unless `allowed_sources` is set.
/// - `manual_listen` addresses use the `manual` policy and take precedence.
#[must_use]
pub fn plan_listeners(interfaces: &[LocalInterface], config: &AgentConfig) -> ListenPlan {
    let mut plan = ListenPlan::default();
    let mut used = BTreeSet::new();
    let port = config.listen_port;

    let manual = config.networks.get(NetworkClass::Manual);
    if manual.listen && manual.attended {
        for ip in &config.manual_listen {
            let owner = interfaces.iter().find_map(|iface| {
                iface
                    .addrs
                    .iter()
                    .find(|net| net.addr() == *ip)
                    .map(|net| (iface, net))
            });
            let Some((iface, net)) = owner else {
                plan.skip(ip.to_string(), "address not found on any interface");
                continue;
            };
            match allowed_sources(NetworkClass::Manual, manual, net) {
                Some(allowed) if used.insert(*ip) => plan.targets.push(ListenTarget {
                    class: NetworkClass::Manual,
                    interface: iface.label.clone(),
                    addr: SocketAddr::new(*ip, port),
                    allowed,
                }),
                Some(_) => {}
                None => plan.skip(ip.to_string(), POINT_TO_POINT),
            }
        }
    }

    for iface in interfaces.iter().filter(|iface| iface.up) {
        let Some(class) = iface.class.filter(|class| *class != NetworkClass::Manual) else {
            continue;
        };
        let policy = config.networks.get(class);
        if !policy.listen {
            plan.skip(
                iface.label.clone(),
                "listening is disabled for this network class",
            );
            continue;
        }
        if !policy.attended {
            plan.skip(
                iface.label.clone(),
                "no session type is enabled for this network class",
            );
            continue;
        }
        for net in &iface.addrs {
            if used.contains(&net.addr()) {
                continue;
            }
            match allowed_sources(class, policy, net) {
                Some(allowed) => {
                    used.insert(net.addr());
                    plan.targets.push(ListenTarget {
                        class,
                        interface: iface.label.clone(),
                        addr: SocketAddr::new(net.addr(), port),
                        allowed,
                    });
                }
                None => plan.skip(format!("{} ({})", iface.label, net.addr()), POINT_TO_POINT),
            }
        }
    }
    plan
}

const POINT_TO_POINT: &str =
    "point-to-point address with no subnet: set `allowed_sources` for this network class";

impl ListenPlan {
    fn skip(&mut self, what: String, reason: &'static str) {
        self.skipped.push(Skipped { what, reason });
    }
}

fn allowed_sources(class: NetworkClass, policy: &NetworkPolicy, net: &IpNet) -> Option<Vec<IpNet>> {
    if !policy.allowed_sources.is_empty() {
        return Some(policy.allowed_sources.clone());
    }
    if class == NetworkClass::Tailscale {
        return Some(vec![TAILSCALE_V4, TAILSCALE_V6]);
    }
    let subnet = net.trunc();
    (subnet.prefix_len() < subnet.max_prefix_len()).then(|| vec![subnet])
}

/// Keeps the Agent's listeners in sync with a [`ListenPlan`].
#[derive(Debug)]
pub struct ListenerSet {
    agent: Agent,
    active: HashMap<SocketAddr, Active>,
    /// Addresses whose bind failed, so the warning is logged once.
    failing: HashSet<SocketAddr>,
}

#[derive(Debug)]
struct Active {
    target: ListenTarget,
    endpoint: quinn::Endpoint,
    task: JoinHandle<()>,
}

impl ListenerSet {
    /// No listeners yet.
    #[must_use]
    pub fn new(agent: Agent) -> Self {
        Self {
            agent,
            active: HashMap::new(),
            failing: HashSet::new(),
        }
    }

    /// Closes listeners that are no longer wanted, opens new ones and
    /// updates the addresses announced to Viewers. Must run inside a Tokio
    /// runtime. Bind failures are logged and retried on the next call.
    pub fn apply(&mut self, targets: &[ListenTarget]) {
        let wanted: HashMap<SocketAddr, &ListenTarget> =
            targets.iter().map(|target| (target.addr, target)).collect();

        self.active.retain(|addr, active| {
            let keep = wanted
                .get(addr)
                .is_some_and(|target| **target == active.target);
            if !keep {
                active.endpoint.close(0u32.into(), b"listener removed");
                active.task.abort();
                tracing::info!(%addr, class = %active.target.class, "stopped listening");
            }
            keep
        });

        for target in targets {
            if self.active.contains_key(&target.addr) {
                continue;
            }
            match self.agent.bind(target.addr) {
                Ok(endpoint) => {
                    self.failing.remove(&target.addr);
                    tracing::info!(
                        addr = %target.addr,
                        class = %target.class,
                        interface = %target.interface,
                        allowed = ?target.allowed,
                        "listening"
                    );
                    let filter = SourceFilter::new(target.allowed.iter().copied());
                    let task = tokio::spawn({
                        let agent = self.agent.clone();
                        let endpoint = endpoint.clone();
                        async move { agent.serve(endpoint, filter).await }
                    });
                    self.active.insert(
                        target.addr,
                        Active {
                            target: target.clone(),
                            endpoint,
                            task,
                        },
                    );
                }
                Err(err) => {
                    if self.failing.insert(target.addr) {
                        tracing::warn!(addr = %target.addr, error = %err, "cannot listen");
                    }
                }
            }
        }

        let mut announced: Vec<CandidateAddr> = self
            .active
            .values()
            .map(|active| CandidateAddr {
                class: active.target.class,
                addr: active.target.addr,
            })
            .collect();
        announced.sort_by_key(|candidate| (candidate.class, candidate.addr));
        self.agent.set_addresses(announced);
    }

    /// Currently open listeners.
    pub fn targets(&self) -> impl Iterator<Item = &ListenTarget> {
        self.active.values().map(|active| &active.target)
    }

    /// Closes every listener.
    pub fn close_all(&mut self) {
        self.apply(&[]);
    }
}

impl Drop for ListenerSet {
    fn drop(&mut self) {
        for active in self.active.values() {
            active.endpoint.close(0u32.into(), b"shutting down");
            active.task.abort();
        }
    }
}

/// Re-scans interfaces every [`RESCAN_INTERVAL`] and keeps listeners in
/// sync until `shutdown` turns `true`. `extra` targets (for example a
/// loopback listener for local tests) are always kept open.
pub async fn run_listeners(
    agent: Agent,
    config: AgentConfig,
    extra: Vec<ListenTarget>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut listeners = ListenerSet::new(agent);
    let mut last_plan = None;
    loop {
        let interfaces = tokio::task::spawn_blocking(discovery::discover)
            .await
            .unwrap_or_default();
        let mut plan = plan_listeners(&interfaces, &config);
        plan.targets.extend(extra.iter().cloned());
        if last_plan.as_ref() != Some(&plan) {
            for skipped in &plan.skipped {
                tracing::info!(what = %skipped.what, reason = skipped.reason, "not listening");
            }
            if plan.targets.is_empty() {
                tracing::warn!(
                    "no interface matches the listening policy; waiting for a VPN to come up"
                );
            }
            listeners.apply(&plan.targets);
            last_plan = Some(plan);
        }

        tokio::select! {
            () = tokio::time::sleep(RESCAN_INTERVAL) => {}
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
    listeners.close_all();
}

/// A loopback listener for local testing (`--listen-loopback`).
#[must_use]
pub fn loopback_target(port: u16) -> ListenTarget {
    ListenTarget {
        class: NetworkClass::Manual,
        interface: "loopback".to_owned(),
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        allowed: vec![IpNet::V4(Ipv4Net::new_assert(
            Ipv4Addr::new(127, 0, 0, 0),
            8,
        ))],
    }
}

#[cfg(test)]
mod tests {
    use rr_config::{Config, NetworkPolicies};

    use super::*;

    fn iface(label: &str, class: Option<NetworkClass>, addrs: &[&str]) -> LocalInterface {
        LocalInterface {
            name: label.to_owned(),
            label: label.to_owned(),
            description: None,
            class,
            up: true,
            addrs: addrs.iter().map(|a| a.parse().unwrap()).collect(),
        }
    }

    fn net(text: &str) -> IpNet {
        text.parse().unwrap()
    }

    #[test]
    fn defaults_listen_on_vpns_only() {
        let interfaces = [
            iface(
                "Tailscale",
                Some(NetworkClass::Tailscale),
                &["100.101.1.2/32", "fd7a:115c:a1e0::5/128"],
            ),
            iface("Radmin VPN", Some(NetworkClass::Radmin), &["26.10.20.30/8"]),
            iface("Ethernet", Some(NetworkClass::Lan), &["192.168.1.10/24"]),
            iface("vEthernet", None, &["172.20.0.1/20"]),
        ];
        let plan = plan_listeners(&interfaces, &Config::default().agent);

        let addrs: Vec<String> = plan.targets.iter().map(|t| t.addr.to_string()).collect();
        assert_eq!(
            addrs,
            [
                "100.101.1.2:7878",
                "[fd7a:115c:a1e0::5]:7878",
                "26.10.20.30:7878"
            ]
        );
        assert_eq!(plan.targets[0].allowed, [TAILSCALE_V4, TAILSCALE_V6]);
        assert_eq!(plan.targets[2].allowed, [net("26.0.0.0/8")]);
        assert_eq!(
            plan.skipped.len(),
            1,
            "the LAN is skipped: {:?}",
            plan.skipped
        );
    }

    #[test]
    fn lan_opt_in_uses_its_subnet_or_the_configured_sources() {
        let interfaces = [iface(
            "Ethernet",
            Some(NetworkClass::Lan),
            &["192.168.1.10/24"],
        )];
        let mut config = Config::default().agent;
        config.networks.lan = NetworkPolicy::ATTENDED_ONLY;
        let plan = plan_listeners(&interfaces, &config);
        assert_eq!(plan.targets[0].allowed, [net("192.168.1.0/24")]);

        // Corporate LAN profile: accept only the VPN client pool.
        config.networks.lan.allowed_sources = vec![net("10.212.134.0/24")];
        let plan = plan_listeners(&interfaces, &config);
        assert_eq!(plan.targets[0].allowed, [net("10.212.134.0/24")]);
    }

    #[test]
    fn point_to_point_needs_explicit_sources() {
        let interfaces = [iface(
            "Forti",
            Some(NetworkClass::FortiClient),
            &["10.212.134.7/32"],
        )];
        let plan = plan_listeners(&interfaces, &Config::default().agent);
        assert!(plan.targets.is_empty());
        assert_eq!(plan.skipped[0].reason, POINT_TO_POINT);
    }

    #[test]
    fn manual_addresses_take_precedence() {
        let interfaces = [iface(
            "Ethernet",
            Some(NetworkClass::Lan),
            &["192.168.1.10/24"],
        )];
        let config = AgentConfig {
            manual_listen: vec!["192.168.1.10".parse().unwrap(), "10.9.9.9".parse().unwrap()],
            networks: NetworkPolicies {
                manual: NetworkPolicy::ATTENDED_ONLY,
                lan: NetworkPolicy::ATTENDED_ONLY,
                ..NetworkPolicies::default()
            },
            ..AgentConfig::default()
        };
        let plan = plan_listeners(&interfaces, &config);
        assert_eq!(plan.targets.len(), 1, "{plan:?}");
        assert_eq!(plan.targets[0].class, NetworkClass::Manual);
        assert_eq!(plan.skipped[0].what, "10.9.9.9");
    }

    #[test]
    fn down_interfaces_and_disabled_classes_are_skipped() {
        let mut down = iface(
            "Tailscale",
            Some(NetworkClass::Tailscale),
            &["100.101.1.2/32"],
        );
        down.up = false;
        let mut config = Config::default().agent;
        config.networks.radmin = NetworkPolicy::DISABLED;
        let plan = plan_listeners(
            &[
                down,
                iface("Radmin VPN", Some(NetworkClass::Radmin), &["26.1.2.3/8"]),
            ],
            &config,
        );
        assert!(plan.targets.is_empty());
        assert_eq!(plan.skipped.len(), 1);
    }

    #[test]
    fn listen_port_is_applied() {
        let config = AgentConfig {
            listen_port: 9100,
            ..AgentConfig::default()
        };
        let plan = plan_listeners(
            &[iface(
                "Tailscale",
                Some(NetworkClass::Tailscale),
                &["100.101.1.2/32"],
            )],
            &config,
        );
        assert_eq!(plan.targets[0].addr.port(), 9100);
    }
}
