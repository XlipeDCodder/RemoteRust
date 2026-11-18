//! Linux backends: X11 (MIT-SHM, XDamage, XFixes, XTest), Wayland
//! (xdg-desktop-portal, PipeWire, libei), uinput/evdev and logind.

pub(crate) mod portal;
pub(crate) mod x11;
pub(crate) mod x11_border;
pub(crate) mod x11_cursor;
pub(crate) mod x11_hotkey;
pub(crate) mod x11_input;

use crate::capture::CaptureError;

/// How the screen is captured in this session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Backend {
    /// X11 root window through MIT-SHM.
    X11,
    /// xdg-desktop-portal ScreenCast + PipeWire (Wayland compositors).
    Portal,
}

/// Picks the capture backend from the session environment.
///
/// `RUSTREMOTE_CAPTURE=x11|portal` overrides the choice. Otherwise a
/// Wayland session uses the portal, even when `DISPLAY` is also set: under
/// XWayland the X11 root window only holds X clients.
pub(crate) fn backend() -> Result<Backend, CaptureError> {
    let var = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
    match var("RUSTREMOTE_CAPTURE").as_deref() {
        Some("x11") => return Ok(Backend::X11),
        Some("portal" | "wayland") => return Ok(Backend::Portal),
        _ => {}
    }
    if var("WAYLAND_DISPLAY").is_some() || var("XDG_SESSION_TYPE").as_deref() == Some("wayland") {
        Ok(Backend::Portal)
    } else if var("DISPLAY").is_some() {
        Ok(Backend::X11)
    } else {
        Err(CaptureError::Unsupported(
            "no graphical session (neither WAYLAND_DISPLAY nor DISPLAY is set)",
        ))
    }
}
