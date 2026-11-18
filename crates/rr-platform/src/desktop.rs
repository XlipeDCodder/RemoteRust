//! Which desktop the local user sees (blueprint v2 §7.3).
//!
//! On Windows, UAC prompts, Ctrl+Alt+Del and the lock screen run on the
//! secure desktop (`Winlogon`), which an unprivileged process can neither
//! capture nor inject into: only the local user can answer there. Screen
//! capture then fails with "access lost", and this tells a desktop switch
//! apart from other interruptions (a resolution change, a full-screen game).
//!
//! Linux has no equivalent: it is always [`InputDesktop::Normal`].

/// The desktop that receives input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputDesktop {
    /// The user's own desktop.
    Normal,
    /// The secure desktop, or any desktop this process may not open.
    Secure,
}

/// Looks at the current input desktop. Cheap enough to call every 250 ms.
#[must_use]
pub fn input_desktop() -> InputDesktop {
    #[cfg(windows)]
    {
        crate::win::desktop::input_desktop()
    }
    #[cfg(not(windows))]
    {
        InputDesktop::Normal
    }
}
