//! RustRemote networking (blueprint v2 §5, §6.1, §7.2–§7.5).
//!
//! Responsibilities:
//! - QUIC endpoints (`quinn`) with mutual TLS 1.3 and pinned device keys;
//! - attended pairing (SPAKE2) and unattended login (OPAQUE), bound to TLS;
//! - interface discovery, VPN classification, per-interface listeners;
//! - Viewer path selection (Happy-Eyeballs race across VPNs).
//!
//! Status: M0 skeleton. Implementation starts in M1.
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
