//! Cursor-stream messages: the Agent's pointer position and shape
//! (blueprint v2 §6.2, §6.4, §8.2 rule 3).
//!
//! The cursor stream is one unidirectional QUIC stream from the Agent.
//! Messages are framed like the control stream with a
//! [`limits::CURSOR`](crate::limits::CURSOR) maximum; shapes are sent once
//! and then referred to by id.

use serde::{Deserialize, Serialize};

use crate::frame::{self, FrameError};
use crate::{BoundedBytes, limits};

/// Largest cursor side, in pixels.
pub const MAX_CURSOR_SIDE: u16 = 256;

/// Largest cursor bitmap: 256 × 256 RGBA.
pub const MAX_CURSOR_BYTES: usize = 256 * 256 * 4;

/// [`CursorMsg::UseCachedShape`] only refers to one of the last this many
/// shapes the Agent sent (oldest forgotten first), so a Viewer that keeps
/// at least this many, by arrival, always has the one it needs.
pub const CACHED_SHAPES: usize = 32;

/// A message on the cursor stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CursorMsg {
    /// Where the pointer is on the captured monitor.
    Position {
        /// 0..=[`COORD_MAX`](crate::input::COORD_MAX), left to right.
        x: u16,
        /// 0..=[`COORD_MAX`](crate::input::COORD_MAX), top to bottom.
        y: u16,
        /// `false` when the pointer is hidden or on another monitor.
        visible: bool,
    },
    /// A new pointer shape, now current. The Viewer caches it under `id`.
    Shape {
        /// Cache key chosen by the Agent.
        id: u32,
        /// Hot spot column (less than `width`).
        hot_x: u16,
        /// Hot spot row (less than `height`).
        hot_y: u16,
        /// Width in pixels, 1..=[`MAX_CURSOR_SIDE`].
        width: u16,
        /// Height in pixels, 1..=[`MAX_CURSOR_SIDE`].
        height: u16,
        /// Straight (not premultiplied) RGBA, row by row:
        /// exactly `width * height * 4` bytes.
        rgba: BoundedBytes<MAX_CURSOR_BYTES>,
    },
    /// A shape sent earlier is current again.
    UseCachedShape {
        /// Its cache key.
        id: u32,
    },
}

/// Encodes `msg` as a frame for the cursor stream.
///
/// # Errors
/// [`FrameError::Invalid`] for an inconsistent shape, or
/// [`FrameError::TooLarge`].
pub fn encode(msg: &CursorMsg) -> Result<Vec<u8>, FrameError> {
    check(msg)?;
    frame::encode(msg, limits::CURSOR)
}

/// Decodes a frame body (prefix removed) and checks the shape fields.
///
/// # Errors
/// [`FrameError::Malformed`], [`FrameError::TrailingBytes`] or
/// [`FrameError::Invalid`].
pub fn decode(body: &[u8]) -> Result<CursorMsg, FrameError> {
    let msg = frame::decode(body)?;
    check(&msg)?;
    Ok(msg)
}

fn check(msg: &CursorMsg) -> Result<(), FrameError> {
    let CursorMsg::Shape {
        hot_x,
        hot_y,
        width,
        height,
        rgba,
        ..
    } = msg
    else {
        return Ok(());
    };
    if *width == 0 || *height == 0 || *width > MAX_CURSOR_SIDE || *height > MAX_CURSOR_SIDE {
        return Err(FrameError::Invalid("cursor size out of range"));
    }
    if hot_x >= width || hot_y >= height {
        return Err(FrameError::Invalid("cursor hot spot outside the shape"));
    }
    let expected = usize::from(*width)
        .checked_mul(usize::from(*height))
        .and_then(|pixels| pixels.checked_mul(4));
    if expected != Some(rgba.len()) {
        return Err(FrameError::Invalid("cursor bitmap size mismatch"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape(width: u16, height: u16, bytes: usize) -> CursorMsg {
        CursorMsg::Shape {
            id: 7,
            hot_x: 0,
            hot_y: 0,
            width,
            height,
            rgba: BoundedBytes::new(vec![0xAB; bytes]).unwrap(),
        }
    }

    #[test]
    fn the_largest_shape_fits_the_limit() {
        let msg = shape(256, 256, MAX_CURSOR_BYTES);
        let encoded = encode(&msg).unwrap();
        assert_eq!(decode(&encoded[frame::PREFIX_LEN..]).unwrap(), msg);
    }

    #[test]
    fn inconsistent_shapes_are_rejected() {
        assert!(encode(&shape(2, 2, 15)).is_err());
        assert!(encode(&shape(0, 2, 0)).is_err());
        assert!(encode(&shape(257, 1, 257 * 4)).is_err());
        let hot_spot_outside = CursorMsg::Shape {
            id: 1,
            hot_x: 2,
            hot_y: 0,
            width: 2,
            height: 1,
            rgba: BoundedBytes::new(vec![0; 8]).unwrap(),
        };
        assert!(encode(&hot_spot_outside).is_err());
        // The same checks apply when decoding.
        let body = postcard::to_allocvec(&shape(2, 2, 15)).unwrap();
        assert!(matches!(decode(&body), Err(FrameError::Invalid(_))));
    }

    proptest::proptest! {
        /// Decoding arbitrary bytes never panics, and shapes that decode are
        /// consistent.
        #[test]
        fn decoding_random_bytes_is_total(body in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..64)) {
            if let Ok(msg) = decode(&body) {
                proptest::prop_assert!(check(&msg).is_ok());
            }
        }
    }

    #[test]
    fn small_messages_round_trip() {
        for msg in [
            CursorMsg::Position {
                x: 0,
                y: u16::MAX,
                visible: true,
            },
            CursorMsg::UseCachedShape { id: u32::MAX },
            shape(32, 32, 32 * 32 * 4),
        ] {
            let encoded = encode(&msg).unwrap();
            assert_eq!(decode(&encoded[frame::PREFIX_LEN..]).unwrap(), msg);
        }
    }
}
