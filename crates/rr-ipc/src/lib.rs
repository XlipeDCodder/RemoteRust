//! Fixed-schema IPC between `rr-agent` (unprivileged) and
//! `rr-desktop-helper` (SYSTEM/root) (blueprint v2 §4.1).
//!
//! The privileged side must only ever parse the small, closed set of messages
//! defined here: validated input events, keyframe requests, rate targets and
//! monitor selection. Everything else is rejected.
//!
//! Status: M0 skeleton. Implementation starts in M5.
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
