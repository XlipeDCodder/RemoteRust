//! Fuzzes the cursor-stream decoder (blueprint v2 §6.3, §7.8): the Viewer
//! parses these messages from the Agent.
//!
//! Properties checked on every input:
//! - nothing panics, whatever the bytes;
//! - a decoded shape is consistent (size, hot spot, bitmap length), and
//!   every decoded message re-encodes to the same value.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rr_proto::cursor::{self, MAX_CURSOR_SIDE};
use rr_proto::{CursorMsg, frame, limits};

fuzz_target!(|data: &[u8]| {
    let _ = cursor::decode(data);

    let Some((prefix, rest)) = data.split_first_chunk::<{ frame::PREFIX_LEN }>() else {
        return;
    };
    let Ok(len) = frame::body_len(*prefix, limits::CURSOR) else {
        return;
    };
    let Some(body) = rest.get(..len) else {
        return;
    };
    if let Ok(msg) = cursor::decode(body) {
        if let CursorMsg::Shape {
            hot_x,
            hot_y,
            width,
            height,
            rgba,
            ..
        } = &msg
        {
            assert!(*width > 0 && *width <= MAX_CURSOR_SIDE && *height <= MAX_CURSOR_SIDE);
            assert!(hot_x < width && hot_y < height);
            assert_eq!(rgba.len(), usize::from(*width) * usize::from(*height) * 4);
        }
        let encoded = cursor::encode(&msg).expect("a decoded message re-encodes");
        let again = cursor::decode(&encoded[frame::PREFIX_LEN..]).expect("a re-encoded message decodes");
        assert_eq!(msg, again, "round trip changed the message");
    }
});
