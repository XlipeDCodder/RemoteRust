//! The input desktop's name (blueprint v2 §7.3).
#![allow(unsafe_code)] // FFI module: every block below is justified with `SAFETY:`.

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, DESKTOP_CONTROL_FLAGS, DESKTOP_READOBJECTS, GetUserObjectInformationW,
    OpenInputDesktop, UOI_NAME,
};

use crate::desktop::InputDesktop;

/// The user's desktop in the interactive window station.
const DEFAULT_DESKTOP: &str = "Default";

pub(crate) fn input_desktop() -> InputDesktop {
    match input_desktop_name() {
        Some(name) if name.eq_ignore_ascii_case(DEFAULT_DESKTOP) => InputDesktop::Normal,
        // `Winlogon`, `Screen-saver`, or no access at all (the secure
        // desktop refuses unprivileged processes).
        _ => InputDesktop::Secure,
    }
}

/// The input desktop's name; `None` if it cannot be opened.
fn input_desktop_name() -> Option<String> {
    // SAFETY: plain call; the handle is closed below.
    let desktop =
        unsafe { OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_READOBJECTS) }.ok()?;
    let mut name = [0_u16; 64];
    let mut needed = 0_u32;
    let size = u32::try_from(size_of_val(&name)).unwrap_or(0);
    // SAFETY: `name` is writable for `size` bytes and `needed` is a valid
    // out-parameter; the desktop handle is open.
    let read = unsafe {
        GetUserObjectInformationW(
            HANDLE(desktop.0),
            UOI_NAME,
            Some(name.as_mut_ptr().cast()),
            size,
            Some(&raw mut needed),
        )
    };
    // SAFETY: the handle opened above, closed once.
    let _ = unsafe { CloseDesktop(desktop) };
    read.ok()?;
    let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    Some(String::from_utf16_lossy(name.get(..len)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "needs the unlocked interactive desktop"]
    fn unlocked_desktop_is_normal() {
        assert_eq!(input_desktop_name().as_deref(), Some(DEFAULT_DESKTOP));
        assert_eq!(input_desktop(), InputDesktop::Normal);
    }
}
