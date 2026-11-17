//! Input-stream messages: keyboard and mouse from the Viewer
//! (blueprint v2 §6.2, §6.4, §8.7).
//!
//! The input stream is one unidirectional QUIC stream opened by the Viewer
//! after `SessionStart`, and only when `CONTROL` was granted. Each message
//! is framed like the control stream (`u32` length prefix + postcard body)
//! with a [`limits::INPUT`](crate::limits::INPUT) maximum.
//!
//! Keys are *physical* keys, named after the W3C UI Events `code` values:
//! the Agent's keyboard layout decides which character a key produces, so
//! dead keys, AltGr and layout-specific keys behave as they do locally on
//! the Agent.

use serde::{Deserialize, Serialize};

/// Mouse coordinates are normalized to the captured monitor: 0 is the left
/// (top) edge and this value the right (bottom) edge.
pub const COORD_MAX: u16 = u16::MAX;

/// One wheel notch, in [`InputMsg::Wheel`] units (as on Windows).
pub const WHEEL_NOTCH: i16 = 120;

macro_rules! key_codes {
    ($($(#[$doc:meta])* $name:ident),* $(,)?) => {
        /// A physical key, named after its W3C UI Events `code` value.
        ///
        /// Wire format: the variant index. Variants are only ever appended;
        /// an unknown index is a protocol error.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        pub enum KeyCode {
            $($(#[$doc])* $name,)*
        }

        impl KeyCode {
            /// Every key, in wire order.
            pub const ALL: &'static [Self] = &[$(Self::$name,)*];

            /// The W3C `code` name, e.g. `KeyA`.
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self {
                    $(Self::$name => stringify!($name),)*
                }
            }
        }
    };
}

key_codes! {
    // Writing system keys.
    /// `` ` `` and `~` on a US keyboard; `'` and `"` on ABNT2.
    Backquote,
    /// `\` and `|` on a US keyboard; `]` and `}` on ABNT2.
    Backslash,
    /// `[` and `{` on a US keyboard; `´` and `` ` `` on ABNT2.
    BracketLeft,
    /// `]` and `}` on a US keyboard; `[` and `{` on ABNT2.
    BracketRight,
    /// `,` and `<`.
    Comma,
    /// `0` and `)`.
    Digit0,
    /// `1` and `!`.
    Digit1,
    /// `2` and `@`.
    Digit2,
    /// `3` and `#`.
    Digit3,
    /// `4` and `$`.
    Digit4,
    /// `5` and `%`.
    Digit5,
    /// `6` and `^` (`¨` on ABNT2).
    Digit6,
    /// `7` and `&`.
    Digit7,
    /// `8` and `*`.
    Digit8,
    /// `9` and `(`.
    Digit9,
    /// `=` and `+`.
    Equal,
    /// The key between left Shift and Z on ISO keyboards (`\` and `|` on ABNT2).
    IntlBackslash,
    /// The key left of right Shift on ABNT2 and JIS keyboards (`/` and `?` on ABNT2).
    IntlRo,
    /// The Yen key on JIS keyboards.
    IntlYen,
    /// `A`.
    KeyA,
    /// `B`.
    KeyB,
    /// `C`.
    KeyC,
    /// `D`.
    KeyD,
    /// `E`.
    KeyE,
    /// `F`.
    KeyF,
    /// `G`.
    KeyG,
    /// `H`.
    KeyH,
    /// `I`.
    KeyI,
    /// `J`.
    KeyJ,
    /// `K`.
    KeyK,
    /// `L`.
    KeyL,
    /// `M`.
    KeyM,
    /// `N`.
    KeyN,
    /// `O`.
    KeyO,
    /// `P`.
    KeyP,
    /// `Q`.
    KeyQ,
    /// `R`.
    KeyR,
    /// `S`.
    KeyS,
    /// `T`.
    KeyT,
    /// `U`.
    KeyU,
    /// `V`.
    KeyV,
    /// `W`.
    KeyW,
    /// `X`.
    KeyX,
    /// `Y`.
    KeyY,
    /// `Z`.
    KeyZ,
    /// `-` and `_`.
    Minus,
    /// `.` and `>`.
    Period,
    /// `'` and `"` on a US keyboard; `~` and `^` on ABNT2.
    Quote,
    /// `;` and `:` on a US keyboard; `ç` on ABNT2.
    Semicolon,
    /// `/` and `?` on a US keyboard; `;` and `:` on ABNT2.
    Slash,
    // Functional keys.
    /// Left Alt.
    AltLeft,
    /// Right Alt (AltGr on many layouts).
    AltRight,
    /// Backspace.
    Backspace,
    /// Caps Lock.
    CapsLock,
    /// The context menu key.
    ContextMenu,
    /// Left Control.
    ControlLeft,
    /// Right Control.
    ControlRight,
    /// Enter.
    Enter,
    /// Left Windows / Super key.
    MetaLeft,
    /// Right Windows / Super key.
    MetaRight,
    /// Left Shift.
    ShiftLeft,
    /// Right Shift.
    ShiftRight,
    /// Space bar.
    Space,
    /// Tab.
    Tab,
    /// Japanese 変換 (henkan).
    Convert,
    /// Japanese カタカナ/ひらがな/ローマ字.
    KanaMode,
    /// Korean Han/Yeong.
    Lang1,
    /// Korean Hanja.
    Lang2,
    /// Japanese 無変換 (muhenkan).
    NonConvert,
    // Control pad.
    /// Delete.
    Delete,
    /// End.
    End,
    /// Home.
    Home,
    /// Insert.
    Insert,
    /// Page Down.
    PageDown,
    /// Page Up.
    PageUp,
    // Arrow pad.
    /// Down arrow.
    ArrowDown,
    /// Left arrow.
    ArrowLeft,
    /// Right arrow.
    ArrowRight,
    /// Up arrow.
    ArrowUp,
    // Numeric keypad.
    /// Num Lock.
    NumLock,
    /// Keypad `0`.
    Numpad0,
    /// Keypad `1`.
    Numpad1,
    /// Keypad `2`.
    Numpad2,
    /// Keypad `3`.
    Numpad3,
    /// Keypad `4`.
    Numpad4,
    /// Keypad `5`.
    Numpad5,
    /// Keypad `6`.
    Numpad6,
    /// Keypad `7`.
    Numpad7,
    /// Keypad `8`.
    Numpad8,
    /// Keypad `9`.
    Numpad9,
    /// Keypad `+`.
    NumpadAdd,
    /// The extra keypad key on ABNT2 (`.`) and JIS (`,`) keyboards.
    NumpadComma,
    /// Keypad decimal separator.
    NumpadDecimal,
    /// Keypad `/`.
    NumpadDivide,
    /// Keypad Enter.
    NumpadEnter,
    /// Keypad `=`.
    NumpadEqual,
    /// Keypad `*`.
    NumpadMultiply,
    /// Keypad `-`.
    NumpadSubtract,
    // Function section.
    /// Escape.
    Escape,
    /// F1.
    F1,
    /// F2.
    F2,
    /// F3.
    F3,
    /// F4.
    F4,
    /// F5.
    F5,
    /// F6.
    F6,
    /// F7.
    F7,
    /// F8.
    F8,
    /// F9.
    F9,
    /// F10.
    F10,
    /// F11.
    F11,
    /// F12.
    F12,
    /// F13.
    F13,
    /// F14.
    F14,
    /// F15.
    F15,
    /// F16.
    F16,
    /// F17.
    F17,
    /// F18.
    F18,
    /// F19.
    F19,
    /// F20.
    F20,
    /// F21.
    F21,
    /// F22.
    F22,
    /// F23.
    F23,
    /// F24.
    F24,
    /// Print Screen.
    PrintScreen,
    /// Scroll Lock.
    ScrollLock,
    /// Pause / Break.
    Pause,
    // Media and browser keys.
    /// Browser back.
    BrowserBack,
    /// Browser favorites.
    BrowserFavorites,
    /// Browser forward.
    BrowserForward,
    /// Browser home.
    BrowserHome,
    /// Browser refresh.
    BrowserRefresh,
    /// Browser search.
    BrowserSearch,
    /// Browser stop.
    BrowserStop,
    /// Launch the mail client.
    LaunchMail,
    /// Media play / pause.
    MediaPlayPause,
    /// Media stop.
    MediaStop,
    /// Next track.
    MediaTrackNext,
    /// Previous track.
    MediaTrackPrevious,
    /// Volume down.
    AudioVolumeDown,
    /// Mute.
    AudioVolumeMute,
    /// Volume up.
    AudioVolumeUp,
}

impl KeyCode {
    /// Whether this is a modifier (Shift, Control, Alt, Meta).
    #[must_use]
    pub const fn is_modifier(self) -> bool {
        matches!(
            self,
            Self::ShiftLeft
                | Self::ShiftRight
                | Self::ControlLeft
                | Self::ControlRight
                | Self::AltLeft
                | Self::AltRight
                | Self::MetaLeft
                | Self::MetaRight
        )
    }
}

/// A mouse button.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MouseButton {
    /// Primary button.
    Left,
    /// Secondary button.
    Right,
    /// Wheel button.
    Middle,
    /// The "back" side button.
    Back,
    /// The "forward" side button.
    Forward,
}

impl MouseButton {
    /// Every button, in wire order.
    pub const ALL: &'static [Self] = &[
        Self::Left,
        Self::Right,
        Self::Middle,
        Self::Back,
        Self::Forward,
    ];
}

/// A message on the input stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InputMsg {
    /// A key went down or up. A second `down` without an `up` in between
    /// is an auto-repeat.
    Key {
        /// The physical key.
        code: KeyCode,
        /// `true` when pressed.
        down: bool,
    },
    /// Absolute pointer position on the captured monitor.
    MouseMove {
        /// The monitor (`MonitorInfo::id`); must be the one being streamed.
        monitor: u8,
        /// 0..=[`COORD_MAX`], left to right.
        x: u16,
        /// 0..=[`COORD_MAX`], top to bottom.
        y: u16,
    },
    /// A mouse button went down or up.
    MouseButton {
        /// Which button.
        button: MouseButton,
        /// `true` when pressed.
        down: bool,
    },
    /// Wheel rotation in 1/120-notch units ([`WHEEL_NOTCH`] per notch).
    Wheel {
        /// Positive scrolls right.
        dx: i16,
        /// Positive scrolls up (wheel turned away from the user).
        dy: i16,
    },
    /// Release every key and button this session pressed.
    ReleaseAll,
    /// Sent periodically while something is held down, so the Agent can
    /// tell a held key from a dead connection and release it in time.
    Held,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{frame, limits};

    #[test]
    fn key_names_are_unique_and_ordered() {
        let mut names: Vec<_> = KeyCode::ALL.iter().map(|key| key.name()).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count);
        // The wire index is the position in `ALL`.
        for (index, key) in KeyCode::ALL.iter().enumerate() {
            let body = postcard::to_allocvec(key).unwrap();
            let decoded: KeyCode = postcard::from_bytes(&body).unwrap();
            assert_eq!(decoded, *key);
            assert_eq!(
                postcard::to_allocvec(&u32::try_from(index).unwrap()).unwrap(),
                body
            );
        }
    }

    #[test]
    fn every_message_fits_the_input_limit() {
        let messages = [
            InputMsg::Key {
                code: KeyCode::AudioVolumeUp,
                down: true,
            },
            InputMsg::MouseMove {
                monitor: u8::MAX,
                x: u16::MAX,
                y: u16::MAX,
            },
            InputMsg::MouseButton {
                button: MouseButton::Forward,
                down: false,
            },
            InputMsg::Wheel {
                dx: i16::MIN,
                dy: i16::MAX,
            },
            InputMsg::ReleaseAll,
            InputMsg::Held,
        ];
        for msg in messages {
            let encoded = frame::encode(&msg, limits::INPUT).unwrap();
            let decoded: InputMsg = frame::decode(&encoded[frame::PREFIX_LEN..]).unwrap();
            assert_eq!(decoded, msg);
        }
    }

    proptest::proptest! {
        /// Decoding arbitrary bytes never panics.
        #[test]
        fn decoding_random_bytes_is_total(body in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..16)) {
            if let Ok(msg) = frame::decode::<InputMsg>(&body) {
                let encoded = frame::encode(&msg, limits::INPUT).unwrap();
                proptest::prop_assert_eq!(frame::decode::<InputMsg>(&encoded[frame::PREFIX_LEN..]).unwrap(), msg);
            }
        }
    }

    #[test]
    fn unknown_key_is_rejected() {
        let past_the_end = u32::try_from(KeyCode::ALL.len()).unwrap();
        let mut body = vec![0]; // InputMsg::Key
        body.extend(postcard::to_allocvec(&past_the_end).unwrap());
        body.push(1);
        assert!(frame::decode::<InputMsg>(&body).is_err());
    }
}
