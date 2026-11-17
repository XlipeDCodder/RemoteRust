//! Fuzzes the video frame header decoder (blueprint v2 §6.3, §7.8).
//!
//! Properties checked on every input:
//! - nothing panics, whatever the bytes;
//! - a header that passes the prefix check and decodes announces a
//!   bitstream within the stream limit, and re-encodes to the same value.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rr_proto::{frame, limits, video};

fuzz_target!(|data: &[u8]| {
    // As a raw header body.
    let _ = video::decode_header(data);

    // As the video stream reads it: prefix, then header.
    let Some((prefix, rest)) = data.split_first_chunk::<{ frame::PREFIX_LEN }>() else {
        return;
    };
    let Ok(len) = video::header_len(*prefix) else {
        return;
    };
    let Some(body) = rest.get(..len) else {
        return;
    };
    if let Ok(header) = video::decode_header(body) {
        assert!(header.len <= limits::VIDEO_FRAME, "oversized bitstream accepted");
        let encoded = video::encode_header(&header).expect("a decoded header re-encodes");
        let again = video::decode_header(&encoded[frame::PREFIX_LEN..])
            .expect("a re-encoded header decodes");
        assert_eq!(header, again, "round trip changed the header");
    }
});
