//! Video stream framing (blueprint v2 §6.2–§6.4).
//!
//! The video stream is one long-lived, ordered, unidirectional QUIC stream
//! from the Agent. Each frame on it is:
//!
//! ```text
//! u32 LE header length | postcard VideoFrameHeader | `header.len` bitstream bytes
//! ```
//!
//! The bitstream is not serde-encoded. Readers check the header length
//! against [`limits::VIDEO_HEADER`](crate::limits::VIDEO_HEADER) and
//! `header.len` against [`limits::VIDEO_FRAME`](crate::limits::VIDEO_FRAME)
//! before allocating anything.

use serde::{Deserialize, Serialize};

use crate::frame::{self, FrameError, PREFIX_LEN};
use crate::limits;

/// Video codec of a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Codec {
    /// H.264 / AVC, Annex B byte stream, no B-frames.
    H264,
}

impl Codec {
    /// Short name for logs and the Viewer overlay.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::H264 => "H.264",
        }
    }
}

/// Time the Agent spent on one frame, per stage, in microseconds
/// (blueprint v2 §8.10). Durations only: the two clocks are never compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AgentTimings {
    /// Acquiring and copying the screen image.
    pub capture_us: u32,
    /// Color conversion (BGRA to YUV).
    pub convert_us: u32,
    /// Encoding.
    pub encode_us: u32,
}

/// Header in front of every encoded frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VideoFrameHeader {
    /// Increases by one per frame sent; a gap means the stream is broken.
    pub frame_id: u64,
    /// Agent monotonic clock at capture, in microseconds.
    pub capture_ts_us: u64,
    /// Whether the frame can be decoded without any earlier frame.
    pub keyframe: bool,
    /// Bitstream format.
    pub codec: Codec,
    /// Picture width in pixels.
    pub width: u16,
    /// Picture height in pixels.
    pub height: u16,
    /// Agent per-stage durations.
    pub timings: AgentTimings,
    /// Screen updates the Agent folded into this frame because the network
    /// or the encoder was busy (the "latest frame wins" drop counter).
    pub skipped: u32,
    /// Length of the bitstream that follows, in bytes.
    pub len: u32,
}

/// Encodes `header` with its length prefix. The bitstream is written
/// separately, right after it.
///
/// # Errors
/// [`FrameError::TooLarge`] if `header.len` exceeds
/// [`limits::VIDEO_FRAME`], or if the header itself does not fit.
pub fn encode_header(header: &VideoFrameHeader) -> Result<Vec<u8>, FrameError> {
    check_header(header)?;
    frame::encode(header, limits::VIDEO_HEADER)
}

/// Validates a header length prefix and returns the header length.
///
/// # Errors
/// [`FrameError::TooLarge`] if it exceeds [`limits::VIDEO_HEADER`].
pub fn header_len(prefix: [u8; PREFIX_LEN]) -> Result<usize, FrameError> {
    frame::body_len(prefix, limits::VIDEO_HEADER)
}

/// Decodes a header body (prefix removed) and checks its fields, including
/// that the announced bitstream fits [`limits::VIDEO_FRAME`].
///
/// # Errors
/// [`FrameError::Malformed`], [`FrameError::TrailingBytes`],
/// [`FrameError::TooLarge`] or [`FrameError::Invalid`].
pub fn decode_header(body: &[u8]) -> Result<VideoFrameHeader, FrameError> {
    let header: VideoFrameHeader = frame::decode(body)?;
    check_header(&header)?;
    Ok(header)
}

fn check_header(header: &VideoFrameHeader) -> Result<(), FrameError> {
    if header.len > limits::VIDEO_FRAME {
        return Err(FrameError::TooLarge {
            len: u64::from(header.len),
            max: limits::VIDEO_FRAME,
        });
    }
    if header.len == 0 {
        return Err(FrameError::Invalid("empty video frame"));
    }
    if header.width == 0 || header.height == 0 {
        return Err(FrameError::Invalid("zero video dimension"));
    }
    if !header.width.is_multiple_of(2) || !header.height.is_multiple_of(2) {
        return Err(FrameError::Invalid("odd video dimension"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn sample() -> VideoFrameHeader {
        VideoFrameHeader {
            frame_id: u64::MAX,
            capture_ts_us: 123_456_789,
            keyframe: true,
            codec: Codec::H264,
            width: 1920,
            height: 1080,
            timings: AgentTimings {
                capture_us: u32::MAX,
                convert_us: 2_000,
                encode_us: 9_000,
            },
            skipped: 3,
            len: limits::VIDEO_FRAME,
        }
    }

    fn split(frame: &[u8]) -> ([u8; PREFIX_LEN], &[u8]) {
        let (prefix, body) = frame.split_first_chunk::<PREFIX_LEN>().unwrap();
        (*prefix, body)
    }

    #[test]
    fn header_round_trips_and_fits_the_limit() {
        let encoded = encode_header(&sample()).unwrap();
        let (prefix, body) = split(&encoded);
        assert_eq!(header_len(prefix).unwrap(), body.len());
        assert!(body.len() <= limits::VIDEO_HEADER as usize);
        assert_eq!(decode_header(body).unwrap(), sample());
    }

    #[test]
    fn invalid_headers_are_rejected() {
        let too_big = VideoFrameHeader {
            len: limits::VIDEO_FRAME + 1,
            ..sample()
        };
        assert!(matches!(
            encode_header(&too_big),
            Err(FrameError::TooLarge { .. })
        ));
        let body = postcard::to_allocvec(&too_big).unwrap();
        assert!(matches!(
            decode_header(&body),
            Err(FrameError::TooLarge { .. })
        ));

        for bad in [
            VideoFrameHeader { len: 0, ..sample() },
            VideoFrameHeader {
                width: 0,
                ..sample()
            },
            VideoFrameHeader {
                height: 1081,
                ..sample()
            },
        ] {
            let body = postcard::to_allocvec(&bad).unwrap();
            assert!(matches!(decode_header(&body), Err(FrameError::Invalid(_))));
        }
        assert!(header_len((limits::VIDEO_HEADER + 1).to_le_bytes()).is_err());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20_000))]

        /// Decoding arbitrary bytes never panics, and a decoded header
        /// re-encodes to the same value.
        #[test]
        fn decoding_random_bytes_is_total(body in proptest::collection::vec(any::<u8>(), 0..128)) {
            if let Ok(header) = decode_header(&body) {
                let encoded = encode_header(&header).unwrap();
                let (_, re_body) = split(&encoded);
                prop_assert_eq!(decode_header(re_body).unwrap(), header);
            }
        }
    }
}
