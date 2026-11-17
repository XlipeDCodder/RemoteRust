//! Physical key tables (blueprint v2 §8.7): protocol [`KeyCode`]s to and
//! from Windows scan codes and Linux evdev codes.
//!
//! One row per key, checked against the USB HID / W3C UI Events mapping
//! that browsers and winit use. Windows scan codes are set 1, with `0xE0`
//! in the high byte for extended keys (e.g. `0xE04B` is the left arrow).
//! X11 key codes are the evdev code + 8 (XKB `evdev` rules); the Wayland
//! RemoteDesktop portal takes evdev codes directly, for keys and for mouse
//! buttons ([`evdev_button`]).

use rr_proto::{KeyCode, MouseButton};

/// How Windows sees one key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsKey {
    /// Set-1 scan code; `0xE0xx` for extended keys.
    pub scancode: u16,
    /// Virtual-key code to inject instead of the scan code, for keys that
    /// do not inject reliably by scan code (Pause, Num Lock, media keys).
    pub vk: Option<u16>,
}

impl WindowsKey {
    /// Whether the scan code has the `0xE0` prefix.
    #[must_use]
    pub const fn extended(self) -> bool {
        self.scancode & 0xFF00 == 0xE000
    }
}

struct Row {
    key: KeyCode,
    scancode: u16,
    vk: u16,
    evdev: u16,
}

const fn row(key: KeyCode, scancode: u16, evdev: u16) -> Row {
    Row {
        key,
        scancode,
        vk: 0,
        evdev,
    }
}

const fn vk_row(key: KeyCode, scancode: u16, vk: u16, evdev: u16) -> Row {
    Row {
        key,
        scancode,
        vk,
        evdev,
    }
}

/// In [`KeyCode::ALL`] order (checked by a test).
#[rustfmt::skip]
const TABLE: &[Row] = &[
    row(KeyCode::Backquote, 0x0029, 41),
    row(KeyCode::Backslash, 0x002B, 43),
    row(KeyCode::BracketLeft, 0x001A, 26),
    row(KeyCode::BracketRight, 0x001B, 27),
    row(KeyCode::Comma, 0x0033, 51),
    row(KeyCode::Digit0, 0x000B, 11),
    row(KeyCode::Digit1, 0x0002, 2),
    row(KeyCode::Digit2, 0x0003, 3),
    row(KeyCode::Digit3, 0x0004, 4),
    row(KeyCode::Digit4, 0x0005, 5),
    row(KeyCode::Digit5, 0x0006, 6),
    row(KeyCode::Digit6, 0x0007, 7),
    row(KeyCode::Digit7, 0x0008, 8),
    row(KeyCode::Digit8, 0x0009, 9),
    row(KeyCode::Digit9, 0x000A, 10),
    row(KeyCode::Equal, 0x000D, 13),
    row(KeyCode::IntlBackslash, 0x0056, 86),
    row(KeyCode::IntlRo, 0x0073, 89),
    row(KeyCode::IntlYen, 0x007D, 124),
    row(KeyCode::KeyA, 0x001E, 30),
    row(KeyCode::KeyB, 0x0030, 48),
    row(KeyCode::KeyC, 0x002E, 46),
    row(KeyCode::KeyD, 0x0020, 32),
    row(KeyCode::KeyE, 0x0012, 18),
    row(KeyCode::KeyF, 0x0021, 33),
    row(KeyCode::KeyG, 0x0022, 34),
    row(KeyCode::KeyH, 0x0023, 35),
    row(KeyCode::KeyI, 0x0017, 23),
    row(KeyCode::KeyJ, 0x0024, 36),
    row(KeyCode::KeyK, 0x0025, 37),
    row(KeyCode::KeyL, 0x0026, 38),
    row(KeyCode::KeyM, 0x0032, 50),
    row(KeyCode::KeyN, 0x0031, 49),
    row(KeyCode::KeyO, 0x0018, 24),
    row(KeyCode::KeyP, 0x0019, 25),
    row(KeyCode::KeyQ, 0x0010, 16),
    row(KeyCode::KeyR, 0x0013, 19),
    row(KeyCode::KeyS, 0x001F, 31),
    row(KeyCode::KeyT, 0x0014, 20),
    row(KeyCode::KeyU, 0x0016, 22),
    row(KeyCode::KeyV, 0x002F, 47),
    row(KeyCode::KeyW, 0x0011, 17),
    row(KeyCode::KeyX, 0x002D, 45),
    row(KeyCode::KeyY, 0x0015, 21),
    row(KeyCode::KeyZ, 0x002C, 44),
    row(KeyCode::Minus, 0x000C, 12),
    row(KeyCode::Period, 0x0034, 52),
    row(KeyCode::Quote, 0x0028, 40),
    row(KeyCode::Semicolon, 0x0027, 39),
    row(KeyCode::Slash, 0x0035, 53),
    row(KeyCode::AltLeft, 0x0038, 56),
    row(KeyCode::AltRight, 0xE038, 100),
    row(KeyCode::Backspace, 0x000E, 14),
    row(KeyCode::CapsLock, 0x003A, 58),
    row(KeyCode::ContextMenu, 0xE05D, 127),
    row(KeyCode::ControlLeft, 0x001D, 29),
    row(KeyCode::ControlRight, 0xE01D, 97),
    row(KeyCode::Enter, 0x001C, 28),
    row(KeyCode::MetaLeft, 0xE05B, 125),
    row(KeyCode::MetaRight, 0xE05C, 126),
    row(KeyCode::ShiftLeft, 0x002A, 42),
    row(KeyCode::ShiftRight, 0x0036, 54),
    row(KeyCode::Space, 0x0039, 57),
    row(KeyCode::Tab, 0x000F, 15),
    row(KeyCode::Convert, 0x0079, 92),
    row(KeyCode::KanaMode, 0x0070, 93),
    row(KeyCode::Lang1, 0x0072, 122),
    row(KeyCode::Lang2, 0x0071, 123),
    row(KeyCode::NonConvert, 0x007B, 94),
    row(KeyCode::Delete, 0xE053, 111),
    row(KeyCode::End, 0xE04F, 107),
    row(KeyCode::Home, 0xE047, 102),
    row(KeyCode::Insert, 0xE052, 110),
    row(KeyCode::PageDown, 0xE051, 109),
    row(KeyCode::PageUp, 0xE049, 104),
    row(KeyCode::ArrowDown, 0xE050, 108),
    row(KeyCode::ArrowLeft, 0xE04B, 105),
    row(KeyCode::ArrowRight, 0xE04D, 106),
    row(KeyCode::ArrowUp, 0xE048, 103),
    // Windows reports Num Lock as 0xE045 and Pause as 0x0045.
    vk_row(KeyCode::NumLock, 0xE045, 0x90, 69),
    row(KeyCode::Numpad0, 0x0052, 82),
    row(KeyCode::Numpad1, 0x004F, 79),
    row(KeyCode::Numpad2, 0x0050, 80),
    row(KeyCode::Numpad3, 0x0051, 81),
    row(KeyCode::Numpad4, 0x004B, 75),
    row(KeyCode::Numpad5, 0x004C, 76),
    row(KeyCode::Numpad6, 0x004D, 77),
    row(KeyCode::Numpad7, 0x0047, 71),
    row(KeyCode::Numpad8, 0x0048, 72),
    row(KeyCode::Numpad9, 0x0049, 73),
    row(KeyCode::NumpadAdd, 0x004E, 78),
    row(KeyCode::NumpadComma, 0x007E, 121),
    row(KeyCode::NumpadDecimal, 0x0053, 83),
    row(KeyCode::NumpadDivide, 0xE035, 98),
    row(KeyCode::NumpadEnter, 0xE01C, 96),
    row(KeyCode::NumpadEqual, 0x0059, 117),
    row(KeyCode::NumpadMultiply, 0x0037, 55),
    row(KeyCode::NumpadSubtract, 0x004A, 74),
    row(KeyCode::Escape, 0x0001, 1),
    row(KeyCode::F1, 0x003B, 59),
    row(KeyCode::F2, 0x003C, 60),
    row(KeyCode::F3, 0x003D, 61),
    row(KeyCode::F4, 0x003E, 62),
    row(KeyCode::F5, 0x003F, 63),
    row(KeyCode::F6, 0x0040, 64),
    row(KeyCode::F7, 0x0041, 65),
    row(KeyCode::F8, 0x0042, 66),
    row(KeyCode::F9, 0x0043, 67),
    row(KeyCode::F10, 0x0044, 68),
    row(KeyCode::F11, 0x0057, 87),
    row(KeyCode::F12, 0x0058, 88),
    row(KeyCode::F13, 0x0064, 183),
    row(KeyCode::F14, 0x0065, 184),
    row(KeyCode::F15, 0x0066, 185),
    row(KeyCode::F16, 0x0067, 186),
    row(KeyCode::F17, 0x0068, 187),
    row(KeyCode::F18, 0x0069, 188),
    row(KeyCode::F19, 0x006A, 189),
    row(KeyCode::F20, 0x006B, 190),
    row(KeyCode::F21, 0x006C, 191),
    row(KeyCode::F22, 0x006D, 192),
    row(KeyCode::F23, 0x006E, 193),
    row(KeyCode::F24, 0x0076, 194),
    row(KeyCode::PrintScreen, 0xE037, 99),
    row(KeyCode::ScrollLock, 0x0046, 70),
    vk_row(KeyCode::Pause, 0x0045, 0x13, 119),
    vk_row(KeyCode::BrowserBack, 0xE06A, 0xA6, 158),
    vk_row(KeyCode::BrowserFavorites, 0xE066, 0xAB, 156),
    vk_row(KeyCode::BrowserForward, 0xE069, 0xA7, 159),
    vk_row(KeyCode::BrowserHome, 0xE032, 0xAC, 172),
    vk_row(KeyCode::BrowserRefresh, 0xE067, 0xA8, 173),
    vk_row(KeyCode::BrowserSearch, 0xE065, 0xAA, 217),
    vk_row(KeyCode::BrowserStop, 0xE068, 0xA9, 128),
    vk_row(KeyCode::LaunchMail, 0xE06C, 0xB4, 155),
    vk_row(KeyCode::MediaPlayPause, 0xE022, 0xB3, 164),
    vk_row(KeyCode::MediaStop, 0xE024, 0xB2, 166),
    vk_row(KeyCode::MediaTrackNext, 0xE019, 0xB0, 163),
    vk_row(KeyCode::MediaTrackPrevious, 0xE010, 0xB1, 165),
    vk_row(KeyCode::AudioVolumeDown, 0xE02E, 0xAE, 114),
    vk_row(KeyCode::AudioVolumeMute, 0xE020, 0xAD, 113),
    vk_row(KeyCode::AudioVolumeUp, 0xE030, 0xAF, 115),
];

fn find(key: KeyCode) -> Option<&'static Row> {
    TABLE.iter().find(|row| row.key == key)
}

/// How Windows sees `key`.
#[must_use]
pub fn windows(key: KeyCode) -> Option<WindowsKey> {
    find(key).map(|row| WindowsKey {
        scancode: row.scancode,
        vk: (row.vk != 0).then_some(row.vk),
    })
}

/// The key with this Windows scan code (`0xE0xx` for extended keys), as a
/// low-level keyboard hook reports it.
#[must_use]
pub fn from_windows_scancode(scancode: u16) -> Option<KeyCode> {
    TABLE
        .iter()
        .find(|row| row.scancode == scancode)
        .map(|row| row.key)
}

/// The key with this Windows virtual-key code, for the keys injected by
/// virtual key (some keyboards report media keys without a scan code).
#[must_use]
pub fn from_windows_vk(vk: u16) -> Option<KeyCode> {
    TABLE
        .iter()
        .find(|row| row.vk != 0 && row.vk == vk)
        .map(|row| row.key)
}

/// The Linux evdev code of `key` (X11 key code = this + 8).
#[must_use]
pub fn evdev(key: KeyCode) -> Option<u16> {
    find(key).map(|row| row.evdev)
}

/// The key with this Linux evdev code.
#[must_use]
pub fn from_evdev(code: u16) -> Option<KeyCode> {
    TABLE
        .iter()
        .find(|row| row.evdev == code)
        .map(|row| row.key)
}

/// The Linux evdev code of a mouse button (`BTN_LEFT` and up), as the
/// RemoteDesktop portal takes it.
#[must_use]
pub const fn evdev_button(button: MouseButton) -> u16 {
    match button {
        MouseButton::Left => 0x110,
        MouseButton::Right => 0x111,
        MouseButton::Middle => 0x112,
        MouseButton::Back => 0x113,
        MouseButton::Forward => 0x114,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn every_key_has_one_row_in_wire_order() {
        assert_eq!(TABLE.len(), KeyCode::ALL.len());
        for (row, key) in TABLE.iter().zip(KeyCode::ALL) {
            assert_eq!(row.key, *key, "table out of order at {}", key.name());
        }
    }

    #[test]
    fn codes_are_unique_and_round_trip() {
        let mut scancodes = HashSet::new();
        let mut evdevs = HashSet::new();
        for &key in KeyCode::ALL {
            let win = windows(key).unwrap();
            assert!(
                scancodes.insert(win.scancode),
                "{} scan code repeated",
                key.name()
            );
            assert_eq!(from_windows_scancode(win.scancode), Some(key));
            if let Some(vk) = win.vk {
                assert_eq!(from_windows_vk(vk), Some(key));
            }
            let code = evdev(key).unwrap();
            assert!(evdevs.insert(code), "{} evdev code repeated", key.name());
            assert_eq!(from_evdev(code), Some(key));
        }
    }

    #[test]
    fn abnt2_keys_are_mapped() {
        // The ISO key left of Z, the /? key left of right Shift and the
        // keypad "." of ABNT2 keyboards.
        let cases = [
            (KeyCode::IntlBackslash, 0x56, 86),
            (KeyCode::IntlRo, 0x73, 89),
            (KeyCode::NumpadComma, 0x7E, 121),
            (KeyCode::Semicolon, 0x27, 39),   // ç
            (KeyCode::BracketLeft, 0x1A, 26), // ´ dead key
            (KeyCode::Quote, 0x28, 40),       // ~ dead key
            (KeyCode::AltRight, 0xE038, 100), // AltGr
        ];
        for (key, scancode, code) in cases {
            assert_eq!(windows(key).unwrap().scancode, scancode, "{}", key.name());
            assert_eq!(evdev(key), Some(code), "{}", key.name());
        }
    }

    #[test]
    fn extended_keys_are_flagged() {
        assert!(windows(KeyCode::ArrowLeft).unwrap().extended());
        assert!(windows(KeyCode::NumpadEnter).unwrap().extended());
        assert!(!windows(KeyCode::Enter).unwrap().extended());
        // Fake shifts (0xE02A) and the AltGr fake control (0x021D) are not
        // keys.
        assert_eq!(from_windows_scancode(0xE02A), None);
        assert_eq!(from_windows_scancode(0x021D), None);
    }
}
