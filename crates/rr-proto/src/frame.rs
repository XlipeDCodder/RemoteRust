//! Length-prefixed framing (blueprint v2 §6.3).
//!
//! A frame is a `u32` little-endian body length followed by a
//! `postcard`-encoded body. Readers must call [`body_len`] on the prefix and
//! only then allocate and read the body.

use serde::Serialize;
use serde::de::DeserializeOwned;

/// Size of the length prefix, in bytes.
pub const PREFIX_LEN: usize = 4;

/// Errors while encoding or decoding frames.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The body is larger than the stream's limit.
    #[error("frame body of {len} bytes exceeds the {max}-byte limit")]
    TooLarge {
        /// Announced or actual body length.
        len: u64,
        /// Stream limit.
        max: u32,
    },
    /// The body does not decode to a valid message.
    #[error("malformed message")]
    Malformed(#[from] postcard::Error),
    /// Bytes remained after a complete message.
    #[error("{0} unexpected trailing bytes")]
    TrailingBytes(usize),
    /// The message decoded but a field is out of range.
    #[error("invalid field: {0}")]
    Invalid(&'static str),
}

/// Encodes `msg` as a complete frame (prefix + body).
///
/// # Errors
/// [`FrameError::TooLarge`] if the body exceeds `max`, or
/// [`FrameError::Malformed`] if serialization fails.
pub fn encode<T: Serialize>(msg: &T, max: u32) -> Result<Vec<u8>, FrameError> {
    let body = postcard::to_allocvec(msg)?;
    let len = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge {
        len: u64::try_from(body.len()).unwrap_or(u64::MAX),
        max,
    })?;
    if len > max {
        return Err(FrameError::TooLarge {
            len: u64::from(len),
            max,
        });
    }
    let mut frame = Vec::with_capacity(body.len().saturating_add(PREFIX_LEN));
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Validates a length prefix against `max` and returns the body length.
///
/// # Errors
/// [`FrameError::TooLarge`] if the announced length exceeds `max`.
pub fn body_len(prefix: [u8; PREFIX_LEN], max: u32) -> Result<usize, FrameError> {
    let len = u32::from_le_bytes(prefix);
    if len > max {
        return Err(FrameError::TooLarge {
            len: u64::from(len),
            max,
        });
    }
    usize::try_from(len).map_err(|_| FrameError::TooLarge {
        len: u64::from(len),
        max,
    })
}

/// Decodes exactly one message from a frame body (prefix already removed).
///
/// # Errors
/// [`FrameError::Malformed`] or [`FrameError::TrailingBytes`].
pub fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, FrameError> {
    let (msg, rest) = postcard::take_from_bytes::<T>(body)?;
    if rest.is_empty() {
        Ok(msg)
    } else {
        Err(FrameError::TrailingBytes(rest.len()))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use proptest::prelude::*;

    use super::*;
    use crate::{
        BoundedBytes, BoundedString, BoundedVec, CandidateAddr, ControlMsg, DesktopState,
        DisconnectReason, Intent, MonitorInfo, NetworkClass, Permissions, limits,
    };

    fn split(frame: &[u8]) -> ([u8; PREFIX_LEN], &[u8]) {
        let (prefix, body) = frame.split_first_chunk::<PREFIX_LEN>().unwrap();
        (*prefix, body)
    }

    fn sample_messages() -> Vec<ControlMsg> {
        vec![
            ControlMsg::ViewerHello {
                device_name: BoundedString::new("office-pc").unwrap(),
                intent: Intent::Pair,
            },
            ControlMsg::AgentHello {
                device_name: BoundedString::new("home-pc").unwrap(),
            },
            ControlMsg::PairingSpake2 {
                msg: BoundedBytes::new(vec![7; 33]).unwrap(),
            },
            ControlMsg::PairingConfirm { mac: [9; 32] },
            ControlMsg::SessionReady,
            ControlMsg::AgentAddresses {
                addrs: BoundedVec::new(vec![CandidateAddr {
                    class: NetworkClass::Tailscale,
                    addr: SocketAddr::from((Ipv4Addr::new(100, 64, 1, 2), 7878)),
                }])
                .unwrap(),
            },
            ControlMsg::Ping { t_us: u64::MAX },
            ControlMsg::Pong { t_us: 0 },
            ControlMsg::Disconnect {
                reason: DisconnectReason::PairingFailed,
            },
            ControlMsg::RequestSession {
                permissions: Permissions::VIEW.union(Permissions::CONTROL),
            },
            ControlMsg::ConsentPending,
            ControlMsg::SessionStart {
                permissions: Permissions::VIEW,
                monitors: BoundedVec::new(vec![MonitorInfo {
                    id: 0,
                    name: BoundedString::new("DISPLAY1").unwrap(),
                    width: 1920,
                    height: 1080,
                    primary: true,
                }])
                .unwrap(),
                monitor: 0,
            },
            ControlMsg::RequestKeyframe,
            ControlMsg::VideoEncoder {
                name: BoundedString::new("openh264 (software)").unwrap(),
            },
            ControlMsg::Disconnect {
                reason: DisconnectReason::ConsentTimeout,
            },
            ControlMsg::DesktopState {
                state: DesktopState::SecureDesktop,
            },
            ControlMsg::DesktopState {
                state: DesktopState::Normal,
            },
            ControlMsg::Disconnect {
                reason: DisconnectReason::StoppedLocally,
            },
            ControlMsg::Disconnect {
                reason: DisconnectReason::RateLimited,
            },
        ]
    }

    #[test]
    fn largest_session_start_fits_the_control_limit() {
        let monitor = MonitorInfo {
            id: u8::MAX,
            name: BoundedString::new("x".repeat(crate::session::MAX_MONITOR_NAME)).unwrap(),
            width: u16::MAX,
            height: u16::MAX,
            primary: true,
        };
        let msg = ControlMsg::SessionStart {
            permissions: Permissions::VIEW,
            monitors: BoundedVec::new(vec![monitor; crate::session::MAX_MONITORS]).unwrap(),
            monitor: 0,
        };
        assert!(encode(&msg, limits::CONTROL).is_ok());
    }

    #[test]
    fn every_message_round_trips() {
        for msg in sample_messages() {
            let frame = encode(&msg, limits::CONTROL).unwrap();
            let (prefix, body) = split(&frame);
            assert_eq!(body_len(prefix, limits::CONTROL).unwrap(), body.len());
            assert_eq!(decode::<ControlMsg>(body).unwrap(), msg);
        }
    }

    #[test]
    fn oversized_prefix_is_rejected_before_reading() {
        let prefix = (limits::CONTROL + 1).to_le_bytes();
        assert!(matches!(
            body_len(prefix, limits::CONTROL),
            Err(FrameError::TooLarge { .. })
        ));
        assert!(body_len(u32::MAX.to_le_bytes(), limits::CONTROL).is_err());
    }

    #[test]
    fn oversized_message_is_not_encoded() {
        let msg = ControlMsg::PairingSpake2 {
            msg: BoundedBytes::new(vec![0; 64]).unwrap(),
        };
        assert!(matches!(encode(&msg, 8), Err(FrameError::TooLarge { .. })));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let frame = encode(&ControlMsg::SessionReady, limits::CONTROL).unwrap();
        let (_, body) = split(&frame);
        let mut padded = body.to_vec();
        padded.push(0);
        assert!(matches!(
            decode::<ControlMsg>(&padded),
            Err(FrameError::TrailingBytes(1))
        ));
    }

    #[test]
    fn unknown_variant_is_rejected() {
        assert!(decode::<ControlMsg>(&[0x7F]).is_err());
        assert!(decode::<ControlMsg>(&[]).is_err());
    }

    #[test]
    fn unknown_desktop_state_is_rejected() {
        let msg = ControlMsg::DesktopState {
            state: DesktopState::SecureDesktop,
        };
        let frame = encode(&msg, limits::CONTROL).unwrap();
        let (_, body) = split(&frame);
        // The state is the last byte; past the known states nothing decodes.
        let mut unknown = body.to_vec();
        *unknown.last_mut().unwrap() = 2;
        assert!(decode::<ControlMsg>(&unknown).is_err());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20_000))]

        /// Decoding arbitrary bytes never panics, and anything that decodes
        /// re-encodes to an equivalent message.
        #[test]
        fn decoding_random_bytes_is_total(body in proptest::collection::vec(any::<u8>(), 0..512)) {
            if let Ok(msg) = decode::<ControlMsg>(&body) {
                let frame = encode(&msg, limits::CONTROL).unwrap();
                let (_, re_body) = split(&frame);
                prop_assert_eq!(decode::<ControlMsg>(re_body).unwrap(), msg);
            }
        }
    }
}
