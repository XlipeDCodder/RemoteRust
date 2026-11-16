//! Fuzzes the control-stream decoder (blueprint v2 §6.3, §7.8).
//!
//! Properties checked on every input:
//! - nothing panics, whatever the bytes;
//! - a frame whose prefix passes the size check and whose body decodes can
//!   be re-encoded, and decoding that again yields the same message.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rr_proto::{ControlMsg, frame, limits};

fuzz_target!(|data: &[u8]| {
    // As a raw body.
    let _ = frame::decode::<ControlMsg>(data);

    // As a complete frame, the way the control stream reads it.
    let Some((prefix, rest)) = data.split_first_chunk::<{ frame::PREFIX_LEN }>() else {
        return;
    };
    let Ok(len) = frame::body_len(*prefix, limits::CONTROL) else {
        return;
    };
    let Some(body) = rest.get(..len) else {
        return;
    };
    if let Ok(msg) = frame::decode::<ControlMsg>(body) {
        let encoded = frame::encode(&msg, limits::CONTROL).expect("a decoded message re-encodes");
        let again = frame::decode::<ControlMsg>(&encoded[frame::PREFIX_LEN..])
            .expect("a re-encoded message decodes");
        assert_eq!(msg, again, "round trip changed the message");
    }
});
