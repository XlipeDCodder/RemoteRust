//! Control-stream messages (blueprint v2 §6.4, §6.5).
//!
//! Session flow on the control stream (opened by the Viewer):
//!
//! ```text
//! Viewer                                   Agent
//!   ViewerHello{intent} ─────────────────►
//!                       ◄───────────────── AgentHello
//!   -- intent = Pair (unknown devices) --
//!   PairingSpake2 (side A) ──────────────►
//!                       ◄───────────────── PairingSpake2 (side B)
//!   PairingConfirm (viewer MAC) ─────────►  verified first
//!                       ◄───────────────── PairingConfirm (agent MAC)
//!   -- both intents --
//!                       ◄───────────────── SessionReady, AgentAddresses
//!   Ping / Pong (either direction) ◄─────►
//!   Disconnect (either direction) ───────►
//! ```

use serde::{Deserialize, Serialize};

use crate::{BoundedBytes, BoundedString, BoundedVec, CandidateAddr, MAX_DEVICE_NAME};

/// What the Viewer wants from this connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Intent {
    /// First contact: run the session-code PAKE and pin each other's keys.
    Pair,
    /// Already paired: start a session.
    Connect,
}

/// Why a connection is being closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisconnectReason {
    /// Orderly shutdown requested by the user.
    Normal,
    /// The Viewer asked to connect but is not paired with this Agent.
    NotPaired,
    /// The Agent is not accepting pairing right now.
    PairingUnavailable,
    /// The session code or the key confirmation was wrong.
    PairingFailed,
    /// Another session is already active.
    Busy,
    /// The peer sent something invalid or unexpected.
    ProtocolError,
    /// The peer took too long to answer.
    Timeout,
    /// The Agent is shutting down.
    ShuttingDown,
}

/// A message on the control stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMsg {
    /// First message from the Viewer.
    ViewerHello {
        /// Name shown on the Agent.
        device_name: BoundedString<MAX_DEVICE_NAME>,
        /// Pair or connect.
        intent: Intent,
    },
    /// First message from the Agent.
    AgentHello {
        /// Name shown on the Viewer.
        device_name: BoundedString<MAX_DEVICE_NAME>,
    },
    /// SPAKE2 message (33 bytes for the Ed25519 group).
    PairingSpake2 {
        /// Opaque SPAKE2 element.
        msg: BoundedBytes<64>,
    },
    /// Key-confirmation MAC binding the PAKE to the TLS session and both keys.
    PairingConfirm {
        /// HMAC-SHA256 tag.
        mac: [u8; 32],
    },
    /// The Agent accepted the session.
    SessionReady,
    /// Addresses at which the Agent can currently be reached.
    AgentAddresses {
        /// Candidate listener addresses.
        addrs: BoundedVec<CandidateAddr, 16>,
    },
    /// Liveness / RTT probe.
    Ping {
        /// Sender's monotonic timestamp, in microseconds. Echoed back.
        t_us: u64,
    },
    /// Answer to [`ControlMsg::Ping`].
    Pong {
        /// The `t_us` value of the ping being answered.
        t_us: u64,
    },
    /// The sender is closing the connection.
    Disconnect {
        /// Why.
        reason: DisconnectReason,
    },
}
