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
pub mod cursor;
pub mod frame;
pub mod input;
mod key;
mod network;
pub mod session;
pub mod video;

pub use bounded::{BoundedBytes, BoundedString, BoundedVec, TooLong};
pub use control::{ControlMsg, DisconnectReason, Intent, MAX_ENCODER_NAME};
pub use cursor::CursorMsg;
pub use frame::FrameError;
pub use input::{InputMsg, KeyCode, MouseButton};
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
    /// Maximum encoded size of one input-stream message.
    pub const INPUT: u32 = 64;
    /// Maximum encoded size of one cursor-stream message: a 256 × 256 RGBA
    /// shape plus its fields.
    pub const CURSOR: u32 = 256 * 1024 + 64;
}

/// What a unidirectional stream carries: its first byte (blueprint v2
/// §6.2). Each kind may be opened at most once per session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamKind {
    /// Agent → Viewer: encoded video frames.
    Video,
    /// Agent → Viewer: pointer position and shape.
    Cursor,
    /// Viewer → Agent: keyboard and mouse.
    Input,
}

impl StreamKind {
    /// The tag written as the stream's first byte.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Video => 0,
            Self::Cursor => 1,
            Self::Input => 2,
        }
    }

    /// Parses a stream's first byte.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(Self::Video),
            1 => Some(Self::Cursor),
            2 => Some(Self::Input),
            _ => None,
        }
    }
}
