//! Fuzzes the input-stream decoder (blueprint v2 §6.3, §7.8): the Agent
//! parses these messages from the Viewer.
//!
//! Properties checked on every input:
//! - nothing panics, whatever the bytes;
//! - a frame whose prefix passes the size check and whose body decodes
//!   re-encodes within the limit to the same message.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rr_proto::{InputMsg, frame, limits};

fuzz_target!(|data: &[u8]| {
    let _ = frame::decode::<InputMsg>(data);

    let Some((prefix, rest)) = data.split_first_chunk::<{ frame::PREFIX_LEN }>() else {
        return;
    };
    let Ok(len) = frame::body_len(*prefix, limits::INPUT) else {
        return;
    };
    let Some(body) = rest.get(..len) else {
        return;
    };
    if let Ok(msg) = frame::decode::<InputMsg>(body) {
        let encoded = frame::encode(&msg, limits::INPUT).expect("a decoded message re-encodes");
        let again = frame::decode::<InputMsg>(&encoded[frame::PREFIX_LEN..])
            .expect("a re-encoded message decodes");
        assert_eq!(msg, again, "round trip changed the message");
    }
});
