//! RustRemote media pipeline (blueprint v2 §8).
//!
//! Responsibilities:
//! - encoder/decoder traits with FFmpeg (hardware: NVENC, AMF, QSV, VA-API,
//!   Media Foundation) and `openh264` (software fallback) backends;
//! - runtime probing of the best working encoder;
//! - the "latest frame wins" pipeline and adaptive rate control.
//!
//! `unsafe_code` is denied at the workspace level. The future FFmpeg wrapper
//! module is the only place allowed to opt out, with `#[allow(unsafe_code)]`
//! on that module and a `// SAFETY:` comment on every block.
//!
//! Status: M0 skeleton. Implementation starts in M2.
