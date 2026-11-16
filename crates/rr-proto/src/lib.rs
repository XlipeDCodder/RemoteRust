//! RustRemote wire protocol: message types, size limits and encoding
//! (blueprint v2 §6).
//!
//! Security invariants for everything in this crate:
//! - lengths are checked against a per-stream maximum *before* any allocation;
//! - decoding is total: no input, however malformed, may cause a panic;
//! - no `unsafe` code.
//!
//! Status: M0 skeleton. Message types, bounded wrapper types and decoders
//! arrive in M1, together with the first fuzz targets.
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

/// QUIC ALPN identifier. It also versions the protocol: any incompatible
/// change bumps the suffix, and peers with different values refuse to talk.
pub const ALPN: &[u8] = b"rustremote/1";
