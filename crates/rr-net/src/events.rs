//! What happened on the Agent, for its audit log and its window
//! (blueprint v2 §7.5, §7.8).
//!
//! Events carry names, fingerprints, addresses and reasons, never secrets:
//! no session codes, keys' private halves or PAKE messages.

use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use rr_proto::{DevicePublicKey, DisconnectReason, Permissions};

use crate::identity::Fingerprint;
use crate::limits::FailureKind;

/// A Viewer, as shown to the local user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    /// Its name (sanitized).
    pub name: String,
    /// Its key's fingerprint.
    pub fingerprint: Fingerprint,
}

impl PeerInfo {
    pub(crate) fn new(name: &str, key: &DevicePublicKey) -> Self {
        Self {
            name: name.to_owned(),
            fingerprint: Fingerprint::of(key),
        }
    }
}

impl fmt::Display for PeerInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\" ({})", self.name, self.fingerprint)
    }
}

/// Something worth recording or showing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AgentEvent {
    /// A connection attempt failed before authentication; the address is
    /// now blocked for `blocked_for`.
    AuthFailed {
        /// Where it came from.
        source: SocketAddr,
        /// What went wrong.
        kind: FailureKind,
        /// How long the address is refused now.
        blocked_for: Duration,
    },
    /// The first refused attempt from an address during its block.
    Blocked {
        /// The refused address.
        source: IpAddr,
        /// Time left on the block.
        remaining: Duration,
    },
    /// Repeated failures suspended pairing of new devices.
    PairingSuspended {
        /// For how long.
        duration: Duration,
    },
    /// A new Viewer paired with the session code.
    Paired {
        /// The new Viewer.
        viewer: PeerInfo,
        /// Where it connected from.
        source: SocketAddr,
    },
    /// A paired Viewer authenticated.
    Connected {
        /// The Viewer.
        viewer: PeerInfo,
        /// Where it connected from.
        source: SocketAddr,
    },
    /// A Viewer asked to see (and maybe control) the screen.
    SessionRequested {
        /// The Viewer.
        viewer: PeerInfo,
        /// What it asked for.
        permissions: Permissions,
    },
    /// The local user accepted.
    SessionAccepted {
        /// The Viewer.
        viewer: PeerInfo,
        /// What was granted.
        permissions: Permissions,
    },
    /// The request was denied, not answered in time, or refused because
    /// the device asked too often.
    SessionRefused {
        /// The Viewer.
        viewer: PeerInfo,
        /// Why.
        reason: DisconnectReason,
    },
    /// A Viewer's connection ended.
    Disconnected {
        /// The Viewer.
        viewer: PeerInfo,
        /// The reason sent to the Viewer, or `None` when it left by itself.
        reason: Option<DisconnectReason>,
        /// How long it was connected.
        duration: Duration,
    },
}
