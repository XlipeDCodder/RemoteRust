//! RustRemote wire protocol: message types, size limits and encoding
//! (blueprint v2 §6).
//!
//! Security invariants for everything in this crate:
//! - lengths are checked against a per-stream maximum *before* any allocation;
//! - decoding is total: no input, however malformed, may cause a panic;
//! - no `unsafe` code.
//!
//! Wire stability: messages are encoded with `postcard`, which identifies enum
//! variants by position. New variants and fields are only ever *appended*;
//! anything incompatible bumps [`ALPN`].
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

pub mod bounded;
pub mod control;
pub mod frame;
mod key;
mod network;
pub mod session;
pub mod video;

pub use bounded::{BoundedBytes, BoundedString, BoundedVec, TooLong};
pub use control::{ControlMsg, DisconnectReason, Intent, MAX_ENCODER_NAME};
pub use frame::FrameError;
pub use key::{DevicePublicKey, KeyParseError};
pub use network::{CandidateAddr, NetworkClass};
pub use session::{MonitorInfo, Permissions};
pub use video::{AgentTimings, Codec, VideoFrameHeader};

/// QUIC ALPN identifier. It also versions the protocol: any incompatible
/// change bumps the suffix, and peers with different values refuse to talk.
pub const ALPN: &[u8] = b"rustremote/1";

/// Maximum length of a device name, in bytes.
pub const MAX_DEVICE_NAME: usize = 64;

/// Per-stream message size limits (blueprint v2 §6.2).
pub mod limits {
    /// Maximum encoded size of one control-stream message.
    pub const CONTROL: u32 = 4 * 1024;
    /// Maximum encoded size of a video frame header.
    pub const VIDEO_HEADER: u32 = 128;
    /// Maximum size of one encoded video frame (the bitstream after the
    /// header).
    pub const VIDEO_FRAME: u32 = 8 * 1024 * 1024;
}
