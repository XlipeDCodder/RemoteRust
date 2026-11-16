//! Network classes and candidate addresses (blueprint v2 §5).

use std::fmt;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// Network classes RustRemote can detect (blueprint v2 §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkClass {
    /// Tailscale (WireGuard).
    Tailscale,
    /// Radmin VPN (Windows only).
    Radmin,
    /// FortiClient SSL-VPN, or a corporate LAN reached through it.
    FortiClient,
    /// Physical LAN interfaces. Disabled by default.
    Lan,
    /// Interfaces or addresses chosen manually by the user.
    Manual,
}

impl NetworkClass {
    /// Every class, in the default Viewer priority order.
    pub const ALL: [Self; 5] = [
        Self::Tailscale,
        Self::Radmin,
        Self::FortiClient,
        Self::Lan,
        Self::Manual,
    ];

    /// Name used in configuration files and logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tailscale => "tailscale",
            Self::Radmin => "radmin",
            Self::FortiClient => "forticlient",
            Self::Lan => "lan",
            Self::Manual => "manual",
        }
    }
}

impl fmt::Display for NetworkClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One address at which an Agent can be reached, tagged with its network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CandidateAddr {
    /// Network the address belongs to.
    pub class: NetworkClass,
    /// UDP socket address of the QUIC listener.
    pub addr: SocketAddr,
}

impl fmt::Display for CandidateAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.addr, self.class)
    }
}
