//! RustRemote OS integration (blueprint v2 §3, §4.1, §8.3, §8.7).
//!
//! This is the only crate where FFI and `unsafe` code may live. Each FFI
//! module opts out of the workspace-wide `unsafe_code = "deny"` explicitly,
//! and every `unsafe` block carries a `// SAFETY:` justification.
//!
//! Platform pieces: [`capture::ScreenCapturer`] (M2),
//! [`input::InputBackend`] and [`cursor`] (M3), [`killswitch`] and
//! [`desktop`] (M4).

#[cfg(not(any(windows, target_os = "linux")))]
compile_error!("RustRemote supports only Windows and Linux (blueprint v2 §2).");

pub mod border;
pub mod capture;
pub mod cursor;
pub mod desktop;
pub mod hook;
pub mod host;
pub mod input;
pub mod keymap;
pub mod killswitch;
pub mod secret;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(windows)]
pub mod win;
