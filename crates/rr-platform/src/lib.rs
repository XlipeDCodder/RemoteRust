//! RustRemote OS integration (blueprint v2 §3, §4.1, §8.3, §8.7).
//!
//! This is the only crate where FFI and `unsafe` code may live. Each FFI
//! module opts out of the workspace-wide `unsafe_code = "deny"` explicitly,
//! and every `unsafe` block carries a `// SAFETY:` justification.
//!
//! Planned platform traits: `ScreenCapturer`, `InputInjector`, `CursorSource`,
//! `DesktopStateWatcher`, `KillSwitchHotkey`, `SessionIndicator`.

#[cfg(not(any(windows, target_os = "linux")))]
compile_error!("RustRemote supports only Windows and Linux (blueprint v2 §2).");

pub mod host;
pub mod secret;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(windows)]
pub mod win;
