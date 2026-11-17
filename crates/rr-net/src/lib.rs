//! RustRemote networking (blueprint v2 §5, §6.1, §7.2–§7.5).
//!
//! Responsibilities:
//! - device identity (Ed25519 key, self-signed certificate, fingerprint);
//! - QUIC endpoints (`quinn`) with mutual TLS 1.3 and pinned device keys;
//! - attended pairing (SPAKE2) and, later, unattended login (OPAQUE), both
//!   bound to the TLS session;
//! - interface discovery, VPN classification, per-interface listeners;
//! - Viewer path selection (Happy-Eyeballs race across VPNs).
#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects
    )
)]

pub mod agent;
mod channel;
pub mod discovery;
mod error;
pub mod identity;
pub mod listen;
pub mod pairing;
pub mod race;
pub mod session;
mod tls;
pub mod video;
pub mod viewer;

pub use agent::{Agent, AgentOptions, SourceFilter};
pub use channel::monotonic_us;
pub use discovery::{LocalInterface, discover};
pub use error::SessionError;
pub use identity::{DeviceIdentity, Fingerprint, IdentityError, default_identity_path};
pub use listen::{ListenPlan, ListenTarget, ListenerSet, plan_listeners, run_listeners};
pub use pairing::{CodePolicy, PairingCodes, SessionCode};
pub use race::RaceError;
pub use session::{
    AgentSession, CONSENT_TIMEOUT, Grant, SessionEvent, SessionHandle, SessionRequest,
};
pub use tls::ViewerAccess;
pub use video::{VideoReceiver, VideoSender};
pub use viewer::{
    PathStats, RemoteEvent, RemoteSession, SessionControl, SessionGrant, StatsSource, Viewer,
    ViewerSession,
};
