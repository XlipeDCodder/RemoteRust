//! The kill-switch hotkey (blueprint v2 §7.6): a key combination on the
//! Agent's own keyboard that ends every session at once.
//!
//! Only **physical** keys count, so a Viewer can neither press the hotkey
//! remotely nor hold a modifier down to keep it from working:
//! - Windows: a low-level keyboard hook that ignores events flagged
//!   `LLKHF_INJECTED` (everything `SendInput` produces, ours included).
//!   The hotkey's main key is taken away from the focused application.
//! - X11: XInput 2 raw key events from every device except the XTEST ones
//!   (where `XTestFakeKeyEvent` input comes from). The events are observed,
//!   not grabbed: a grab would also fire for injected keys.
//! - Wayland: no global hotkey (the compositor owns the keyboard); the
//!   tray and window buttons remain, and GNOME's own sharing indicator.
//!
//! The modifier state is tracked from those physical events alone, never
//! from the system's view of the keyboard, which includes injected keys.

use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

use crate::input::{InputError, KeyCode};

/// Modifier keys of a [`Hotkey`]; either side counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Modifiers(u8);

impl Modifiers {
    /// Control.
    pub const CTRL: Self = Self(1);
    /// Alt (also AltGr, which is the right Alt key).
    pub const ALT: Self = Self(2);
    /// Shift.
    pub const SHIFT: Self = Self(4);
    /// The Windows / Super / Meta key.
    pub const SUPER: Self = Self(8);

    /// No modifier.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Whether every modifier of `other` is in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Both sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether no modifier is set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The modifier a key is, if it is one.
    #[must_use]
    pub const fn of(key: KeyCode) -> Option<Self> {
        match key {
            KeyCode::ControlLeft | KeyCode::ControlRight => Some(Self::CTRL),
            KeyCode::AltLeft | KeyCode::AltRight => Some(Self::ALT),
            KeyCode::ShiftLeft | KeyCode::ShiftRight => Some(Self::SHIFT),
            KeyCode::MetaLeft | KeyCode::MetaRight => Some(Self::SUPER),
            _ => None,
        }
    }
}

/// A key combination: modifiers plus one other key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hotkey {
    /// Modifiers that must be held.
    pub modifiers: Modifiers,
    /// The key that completes the combination.
    pub key: KeyCode,
}

impl Hotkey {
    /// Ctrl+Alt+Shift+F12, the default (blueprint v2 §7.6).
    pub const DEFAULT: Self = Self {
        modifiers: Modifiers(Modifiers::CTRL.0 | Modifiers::ALT.0 | Modifiers::SHIFT.0),
        key: KeyCode::F12,
    };
}

/// Why a hotkey string was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HotkeyError {
    /// A part is neither a modifier nor a known key.
    #[error("unknown key \"{0}\" (use names like Ctrl, Alt, Shift, Super, F12, KeyK, Digit1)")]
    UnknownKey(String),
    /// No modifier: a single key would fire during normal typing.
    #[error("a hotkey needs at least one modifier (Ctrl, Alt, Shift or Super)")]
    NoModifier,
    /// Zero or several non-modifier keys.
    #[error("a hotkey needs exactly one key besides the modifiers")]
    KeyCount,
}

impl FromStr for Hotkey {
    type Err = HotkeyError;

    /// Parses `Ctrl+Alt+Shift+F12`: modifiers and one key, joined by `+`,
    /// case-insensitive. Keys use W3C `code` names (`F12`, `KeyK`,
    /// `Digit1`, `Pause`); a single letter or digit is accepted too.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let mut modifiers = Modifiers::empty();
        let mut key = None;
        for part in text.split('+').map(str::trim) {
            let modifier = match part.to_ascii_lowercase().as_str() {
                "ctrl" | "control" => Some(Modifiers::CTRL),
                "alt" | "option" => Some(Modifiers::ALT),
                "shift" => Some(Modifiers::SHIFT),
                "super" | "win" | "windows" | "meta" | "cmd" => Some(Modifiers::SUPER),
                _ => None,
            };
            if let Some(modifier) = modifier {
                modifiers = modifiers.union(modifier);
                continue;
            }
            let code = key_named(part).ok_or_else(|| HotkeyError::UnknownKey(part.to_owned()))?;
            if let Some(modifier) = Modifiers::of(code) {
                modifiers = modifiers.union(modifier);
            } else if key.replace(code).is_some() {
                return Err(HotkeyError::KeyCount);
            }
        }
        let key = key.ok_or(HotkeyError::KeyCount)?;
        if modifiers.is_empty() {
            return Err(HotkeyError::NoModifier);
        }
        Ok(Self { modifiers, key })
    }
}

impl fmt::Display for Hotkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (modifier, name) in [
            (Modifiers::CTRL, "Ctrl"),
            (Modifiers::ALT, "Alt"),
            (Modifiers::SHIFT, "Shift"),
            (Modifiers::SUPER, "Super"),
        ] {
            if self.modifiers.contains(modifier) {
                write!(f, "{name}+")?;
            }
        }
        let name = self.key.name();
        let short = name
            .strip_prefix("Key")
            .or_else(|| name.strip_prefix("Digit"))
            .unwrap_or(name);
        f.write_str(short)
    }
}

/// A key by W3C name, case-insensitive; `K` and `1` mean `KeyK`, `Digit1`.
fn key_named(name: &str) -> Option<KeyCode> {
    let mut chars = name.chars();
    if let (Some(c), None) = (chars.next(), chars.next()) {
        let long = if c.is_ascii_alphabetic() {
            format!("Key{}", c.to_ascii_uppercase())
        } else if c.is_ascii_digit() {
            format!("Digit{c}")
        } else {
            String::new()
        };
        return KeyCode::ALL.iter().copied().find(|key| key.name() == long);
    }
    KeyCode::ALL
        .iter()
        .copied()
        .find(|key| key.name().eq_ignore_ascii_case(name))
}

/// What a physical key event means for the hotkey.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing to do; the event goes on as usual.
    Pass,
    /// The hotkey fired: the main key's press. Platforms that can take
    /// keys away from the system take this one.
    Fired,
    /// The release of a press that fired: taken as well, so the system
    /// never sees half a keystroke.
    Swallow,
}

/// Recognizes the hotkey in a stream of physical key events.
#[derive(Debug, Clone)]
pub struct Detector {
    hotkey: Hotkey,
    held: HashSet<KeyCode>,
    /// The main key's press fired and its release is still due.
    fired: bool,
}

impl Detector {
    /// Watches for `hotkey`.
    #[must_use]
    pub fn new(hotkey: Hotkey) -> Self {
        Self {
            hotkey,
            held: HashSet::new(),
            fired: false,
        }
    }

    /// One physical key event (repeats included).
    pub fn on_key(&mut self, key: KeyCode, down: bool) -> Verdict {
        if !down {
            self.held.remove(&key);
            if key == self.hotkey.key && self.fired {
                self.fired = false;
                return Verdict::Swallow;
            }
            return Verdict::Pass;
        }
        let repeat = !self.held.insert(key);
        if key != self.hotkey.key {
            return Verdict::Pass;
        }
        if self.fired {
            // Auto-repeat of a press that already fired: keep it away from
            // the system, do not fire again.
            return Verdict::Swallow;
        }
        if !repeat && self.held_modifiers().contains(self.hotkey.modifiers) {
            self.fired = true;
            return Verdict::Fired;
        }
        Verdict::Pass
    }

    fn held_modifiers(&self) -> Modifiers {
        self.held
            .iter()
            .filter_map(|key| Modifiers::of(*key))
            .fold(Modifiers::empty(), Modifiers::union)
    }
}

/// The installed hotkey; removed on drop.
pub struct KillSwitch {
    #[cfg(windows)]
    _hook: crate::win::hook::Hook,
    #[cfg(target_os = "linux")]
    _watch: crate::linux::x11_hotkey::Watch,
}

impl KillSwitch {
    /// Starts watching the physical keyboard for `hotkey`; `on_trigger`
    /// runs on the watcher's own thread and must return quickly (on
    /// Windows the whole desktop's keyboard waits for it).
    ///
    /// # Errors
    /// [`InputError::Unsupported`] on Wayland and in sessions without a
    /// keyboard to watch; OS failures.
    pub fn install(
        hotkey: Hotkey,
        on_trigger: impl Fn() + Send + 'static,
    ) -> Result<Self, InputError> {
        #[cfg(windows)]
        {
            let hook = crate::win::hook::install_kill_switch(Detector::new(hotkey), on_trigger)?;
            Ok(Self { _hook: hook })
        }
        #[cfg(target_os = "linux")]
        {
            match crate::linux::backend() {
                Ok(crate::linux::Backend::X11) => {}
                _ => {
                    return Err(InputError::Unsupported(
                        "no global hotkey on Wayland: use the tray or window button",
                    ));
                }
            }
            let watch = crate::linux::x11_hotkey::watch(Detector::new(hotkey), on_trigger)?;
            Ok(Self { _watch: watch })
        }
    }
}

impl fmt::Debug for KillSwitch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KillSwitch").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Hotkey, HotkeyError> {
        text.parse()
    }

    #[test]
    fn parses_and_prints_hotkeys() {
        assert_eq!(parse("Ctrl+Alt+Shift+F12"), Ok(Hotkey::DEFAULT));
        assert_eq!(parse(" control + ALT+shift+f12 "), Ok(Hotkey::DEFAULT));
        assert_eq!(Hotkey::DEFAULT.to_string(), "Ctrl+Alt+Shift+F12");
        let hotkey = parse("Super+Shift+k").unwrap();
        assert_eq!(hotkey.key, KeyCode::KeyK);
        assert_eq!(hotkey.to_string(), "Shift+Super+K");
        assert_eq!(parse("Win+Digit1").unwrap().key, KeyCode::Digit1);
        assert_eq!(parse("Ctrl+Pause").unwrap().key, KeyCode::Pause);
        // Modifier keys by name count as modifiers.
        assert_eq!(
            parse("ControlLeft+AltRight+ShiftLeft+F12"),
            Ok(Hotkey::DEFAULT)
        );
        // Round trip.
        for text in ["Ctrl+Alt+Shift+F12", "Shift+Super+K", "Alt+1", "Ctrl+Pause"] {
            assert_eq!(parse(text).unwrap().to_string(), text);
        }
    }

    #[test]
    fn rejects_bad_hotkeys() {
        assert_eq!(parse("F12"), Err(HotkeyError::NoModifier));
        assert_eq!(parse("Ctrl+Alt"), Err(HotkeyError::KeyCount));
        assert_eq!(parse("Ctrl+F11+F12"), Err(HotkeyError::KeyCount));
        assert_eq!(parse(""), Err(HotkeyError::UnknownKey(String::new())));
        assert_eq!(
            parse("Ctrl+Hyper+F12"),
            Err(HotkeyError::UnknownKey("Hyper".to_owned()))
        );
        assert!(matches!(parse("Ctrl+é"), Err(HotkeyError::UnknownKey(_))));
    }

    fn press(detector: &mut Detector, keys: &[KeyCode]) -> Vec<Verdict> {
        keys.iter().map(|key| detector.on_key(*key, true)).collect()
    }

    fn release(detector: &mut Detector, keys: &[KeyCode]) -> Vec<Verdict> {
        keys.iter()
            .map(|key| detector.on_key(*key, false))
            .collect()
    }

    use KeyCode::{AltLeft, AltRight, ControlLeft, ControlRight, F11, F12, KeyA, ShiftLeft};
    use Verdict::{Fired, Pass, Swallow};

    #[test]
    fn fires_once_on_the_full_combination() {
        let mut detector = Detector::new(Hotkey::DEFAULT);
        assert_eq!(
            press(&mut detector, &[ControlLeft, AltLeft, ShiftLeft, F12]),
            [Pass, Pass, Pass, Fired]
        );
        // Auto-repeat neither fires again nor reaches the system.
        assert_eq!(press(&mut detector, &[F12, F12]), [Swallow, Swallow]);
        assert_eq!(release(&mut detector, &[F12]), [Swallow]);
        assert_eq!(
            release(&mut detector, &[ShiftLeft, AltLeft, ControlLeft]),
            [Pass, Pass, Pass]
        );
        // Again, with the right-hand modifiers (AltGr is the right Alt).
        assert_eq!(
            press(&mut detector, &[ControlRight, AltRight, ShiftLeft, F12]),
            [Pass, Pass, Pass, Fired]
        );
    }

    #[test]
    fn needs_every_modifier_and_the_right_key() {
        let mut detector = Detector::new(Hotkey::DEFAULT);
        assert_eq!(
            press(&mut detector, &[ControlLeft, AltLeft, F12]),
            [Pass; 3]
        );
        release(&mut detector, &[F12]);
        assert_eq!(press(&mut detector, &[ShiftLeft, F11, KeyA]), [Pass; 3]);
        // The key first, modifiers after: not the combination.
        let mut detector = Detector::new(Hotkey::DEFAULT);
        assert_eq!(
            press(&mut detector, &[F12, ControlLeft, AltLeft, ShiftLeft, F12]),
            [Pass; 5]
        );
    }

    #[test]
    fn releasing_a_modifier_disarms() {
        let mut detector = Detector::new(Hotkey::DEFAULT);
        press(&mut detector, &[ControlLeft, AltLeft, ShiftLeft]);
        release(&mut detector, &[AltLeft]);
        assert_eq!(press(&mut detector, &[F12]), [Pass]);
        release(&mut detector, &[F12]);
        assert_eq!(press(&mut detector, &[AltLeft, F12]), [Pass, Fired]);
    }

    #[test]
    fn extra_modifiers_do_not_block_it() {
        // A Viewer cannot block the hotkey by holding keys: injected keys
        // never reach the detector, and extra physical modifiers are fine.
        let mut detector = Detector::new(Hotkey::DEFAULT);
        assert_eq!(
            press(
                &mut detector,
                &[
                    KeyCode::MetaLeft,
                    ControlLeft,
                    AltLeft,
                    ShiftLeft,
                    KeyA,
                    F12
                ]
            ),
            [Pass, Pass, Pass, Pass, Pass, Fired]
        );
    }
}
