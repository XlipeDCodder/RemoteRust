//! Local keyboard and mouse sent to the Agent (blueprint v2 §8.7).
//!
//! Keys travel as physical keys (W3C `code`): the Agent's keyboard layout
//! decides the characters, so ABNT2 and US keyboards work in both
//! directions. Pointer moves go out at most every 4 ms, always before the
//! next key, button or wheel event so that clicks land where they should.
//!
//! While anything is held, the Agent hears from the Viewer at least every
//! 250 ms (`Held` if nothing else); after one second of silence it releases
//! everything by itself. Losing the focus releases everything at once.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use rr_net::InputSender;
use rr_proto::{InputMsg, KeyCode, MouseButton, input::COORD_MAX};
use tokio::sync::mpsc;
use winit::keyboard::KeyCode as WinitKey;

use crate::render::PictureRect;

/// Least time between two pointer moves sent.
const MOVE_SPACING: Duration = Duration::from_millis(4);
/// Longest silence while something is held.
const HELD_PERIOD: Duration = Duration::from_millis(250);
/// Touchpad scrolling: pixels per wheel notch.
const PIXELS_PER_NOTCH: f64 = 60.0;
/// Wheel units per notch.
const NOTCH: f64 = 120.0;

/// Writes queued input to the stream; finishes it when the window is done.
pub async fn send(mut sender: InputSender, mut queue: mpsc::UnboundedReceiver<InputMsg>) {
    while let Some(msg) = queue.recv().await {
        if let Err(err) = sender.send(&msg).await {
            tracing::debug!(error = %err, "input stream closed");
            return;
        }
    }
    sender.finish();
}

/// What the Viewer has pressed on the Agent, and the pacing of moves.
pub struct RemoteInput {
    queue: mpsc::UnboundedSender<InputMsg>,
    monitor: u8,
    keys: BTreeSet<KeyCode>,
    buttons: BTreeSet<MouseButton>,
    pending_move: Option<(u16, u16)>,
    last_move: Option<Instant>,
    last_sent: Option<Instant>,
    /// Touchpad scrolling not yet sent, in wheel units.
    wheel_rest: (f64, f64),
}

impl RemoteInput {
    /// Input for `monitor`, sent through `queue`.
    pub const fn new(queue: mpsc::UnboundedSender<InputMsg>, monitor: u8) -> Self {
        Self {
            queue,
            monitor,
            keys: BTreeSet::new(),
            buttons: BTreeSet::new(),
            pending_move: None,
            last_move: None,
            last_sent: None,
            wheel_rest: (0.0, 0.0),
        }
    }

    fn send(&mut self, msg: InputMsg, now: Instant) {
        // A closed queue means the session is ending; nothing to do.
        let _ = self.queue.send(msg);
        self.last_sent = Some(now);
    }

    fn flush_move(&mut self, now: Instant) {
        if let Some((x, y)) = self.pending_move.take() {
            let monitor = self.monitor;
            self.send(InputMsg::MouseMove { monitor, x, y }, now);
            self.last_move = Some(now);
        }
    }

    /// Presses (again, for an auto-repeat) or releases `key`. A release of
    /// a key not pressed here (e.g. pressed before the focus came) is not
    /// sent.
    pub fn key(&mut self, key: KeyCode, down: bool, now: Instant) {
        if !down && !self.keys.remove(&key) {
            return;
        }
        if down {
            self.keys.insert(key);
        }
        self.flush_move(now);
        self.send(InputMsg::Key { code: key, down }, now);
    }

    /// Moves the pointer, at most every [`MOVE_SPACING`]; the latest
    /// position waits for [`RemoteInput::tick`] otherwise.
    pub fn move_to(&mut self, x: u16, y: u16, now: Instant) {
        self.pending_move = Some((x, y));
        if self
            .last_move
            .is_none_or(|at| now.saturating_duration_since(at) >= MOVE_SPACING)
        {
            self.flush_move(now);
        }
    }

    /// Presses or releases `button`; a release of a button not pressed
    /// here is not sent.
    pub fn button(&mut self, button: MouseButton, down: bool, now: Instant) {
        let changed = if down {
            self.buttons.insert(button)
        } else {
            self.buttons.remove(&button)
        };
        if changed {
            self.flush_move(now);
            self.send(InputMsg::MouseButton { button, down }, now);
        }
    }

    /// A mouse wheel: whole or fractional notches (`y > 0` up, `x > 0`
    /// right).
    pub fn wheel_notches(&mut self, x: f64, y: f64, now: Instant) {
        self.wheel_units(x * NOTCH, y * NOTCH, now);
    }

    /// A touchpad: pixels of scrolling (`y > 0` up, `x > 0` right).
    pub fn wheel_pixels(&mut self, x: f64, y: f64, now: Instant) {
        self.wheel_units(
            x * NOTCH / PIXELS_PER_NOTCH,
            y * NOTCH / PIXELS_PER_NOTCH,
            now,
        );
    }

    fn wheel_units(&mut self, x: f64, y: f64, now: Instant) {
        let (rest_x, rest_y) = (self.wheel_rest.0 + x, self.wheel_rest.1 + y);
        let (dx, dy) = (whole(rest_x), whole(rest_y));
        self.wheel_rest = (rest_x - f64::from(dx), rest_y - f64::from(dy));
        if dx != 0 || dy != 0 {
            self.flush_move(now);
            self.send(InputMsg::Wheel { dx, dy }, now);
        }
    }

    /// Whether any key or button is held on the Agent.
    pub fn holding(&self) -> bool {
        !self.keys.is_empty() || !self.buttons.is_empty()
    }

    /// Whether a mouse button is held (a drag keeps following the pointer
    /// outside the picture).
    pub fn dragging(&self) -> bool {
        !self.buttons.is_empty()
    }

    /// Releases everything held on the Agent (focus lost, window closing).
    pub fn release_all(&mut self, now: Instant) {
        self.flush_move(now);
        if self.holding() {
            self.keys.clear();
            self.buttons.clear();
            self.send(InputMsg::ReleaseAll, now);
        }
    }

    /// Sends what is due: a waiting pointer move, or `Held`. Returns when
    /// to call again, if anything will be due.
    pub fn tick(&mut self, now: Instant) -> Option<Instant> {
        let move_due = self.last_move.map(|at| at + MOVE_SPACING);
        if self.pending_move.is_some() && move_due.is_none_or(|due| now >= due) {
            self.flush_move(now);
        }
        let held_due = self.last_sent.map(|at| at + HELD_PERIOD);
        if self.holding() && held_due.is_none_or(|due| now >= due) {
            self.send(InputMsg::Held, now);
        }
        let next_move = self.pending_move.and(move_due);
        let next_held = self
            .holding()
            .then(|| self.last_sent.map(|at| at + HELD_PERIOD))
            .flatten();
        match (next_move, next_held) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

impl Drop for RemoteInput {
    fn drop(&mut self) {
        self.release_all(Instant::now());
    }
}

/// The integer part of `value`, as wheel units on the wire.
#[allow(clippy::cast_possible_truncation)] // clamped to the i16 range first
fn whole(value: f64) -> i16 {
    value
        .trunc()
        .clamp(f64::from(i16::MIN), f64::from(i16::MAX)) as i16
}

/// Protocol coordinates (`0..=65535` across the picture) of window pixel
/// position `position`. `None` outside the picture, unless `clamp` (during
/// a drag), which pins it to the nearest edge.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // clamped first
pub fn picture_coords(position: (f64, f64), rect: PictureRect, clamp: bool) -> Option<(u16, u16)> {
    let (width, height) = (f64::from(rect.width), f64::from(rect.height));
    if width < 1.0 || height < 1.0 {
        return None;
    }
    let fx = (position.0 - f64::from(rect.x)) / width;
    let fy = (position.1 - f64::from(rect.y)) / height;
    let inside = (0.0..1.0).contains(&fx) && (0.0..1.0).contains(&fy);
    if !inside && !clamp {
        return None;
    }
    let max = f64::from(COORD_MAX);
    let coord = |fraction: f64| (fraction * 65_536.0).floor().clamp(0.0, max) as u16;
    Some((coord(fx), coord(fy)))
}

/// Maps the protocol keys that winit names identically.
macro_rules! same_names {
    ($($name:ident),* $(,)?) => {
        /// The protocol key for a winit physical key, if it has one.
        pub const fn key_code(code: WinitKey) -> Option<KeyCode> {
            Some(match code {
                $(WinitKey::$name => KeyCode::$name,)*
                WinitKey::SuperLeft => KeyCode::MetaLeft,
                WinitKey::SuperRight => KeyCode::MetaRight,
                _ => return None,
            })
        }

        /// Every winit key [`key_code`] maps.
        #[cfg(test)]
        const MAPPED: &[WinitKey] = &[$(WinitKey::$name,)* WinitKey::SuperLeft, WinitKey::SuperRight];
    };
}

same_names!(
    Backquote,
    Backslash,
    BracketLeft,
    BracketRight,
    Comma,
    Digit0,
    Digit1,
    Digit2,
    Digit3,
    Digit4,
    Digit5,
    Digit6,
    Digit7,
    Digit8,
    Digit9,
    Equal,
    IntlBackslash,
    IntlRo,
    IntlYen,
    KeyA,
    KeyB,
    KeyC,
    KeyD,
    KeyE,
    KeyF,
    KeyG,
    KeyH,
    KeyI,
    KeyJ,
    KeyK,
    KeyL,
    KeyM,
    KeyN,
    KeyO,
    KeyP,
    KeyQ,
    KeyR,
    KeyS,
    KeyT,
    KeyU,
    KeyV,
    KeyW,
    KeyX,
    KeyY,
    KeyZ,
    Minus,
    Period,
    Quote,
    Semicolon,
    Slash,
    AltLeft,
    AltRight,
    Backspace,
    CapsLock,
    ContextMenu,
    ControlLeft,
    ControlRight,
    Enter,
    ShiftLeft,
    ShiftRight,
    Space,
    Tab,
    Convert,
    KanaMode,
    Lang1,
    Lang2,
    NonConvert,
    Delete,
    End,
    Home,
    Insert,
    PageDown,
    PageUp,
    ArrowDown,
    ArrowLeft,
    ArrowRight,
    ArrowUp,
    NumLock,
    Numpad0,
    Numpad1,
    Numpad2,
    Numpad3,
    Numpad4,
    Numpad5,
    Numpad6,
    Numpad7,
    Numpad8,
    Numpad9,
    NumpadAdd,
    NumpadComma,
    NumpadDecimal,
    NumpadDivide,
    NumpadEnter,
    NumpadEqual,
    NumpadMultiply,
    NumpadSubtract,
    Escape,
    F1,
    F2,
    F3,
    F4,
    F5,
    F6,
    F7,
    F8,
    F9,
    F10,
    F11,
    F12,
    F13,
    F14,
    F15,
    F16,
    F17,
    F18,
    F19,
    F20,
    F21,
    F22,
    F23,
    F24,
    PrintScreen,
    ScrollLock,
    Pause,
    BrowserBack,
    BrowserFavorites,
    BrowserForward,
    BrowserHome,
    BrowserRefresh,
    BrowserSearch,
    BrowserStop,
    LaunchMail,
    MediaPlayPause,
    MediaStop,
    MediaTrackNext,
    MediaTrackPrevious,
    AudioVolumeDown,
    AudioVolumeMute,
    AudioVolumeUp,
);

/// The protocol button for a winit mouse button, if it has one.
pub const fn mouse_button(button: winit::event::MouseButton) -> Option<MouseButton> {
    use winit::event::MouseButton as W;
    Some(match button {
        W::Left => MouseButton::Left,
        W::Right => MouseButton::Right,
        W::Middle => MouseButton::Middle,
        W::Back => MouseButton::Back,
        W::Forward => MouseButton::Forward,
        W::Other(_) => return None,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    fn input() -> (RemoteInput, mpsc::UnboundedReceiver<InputMsg>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (RemoteInput::new(tx, 2), rx)
    }

    fn drain(rx: &mut mpsc::UnboundedReceiver<InputMsg>) -> Vec<InputMsg> {
        std::iter::from_fn(|| rx.try_recv().ok()).collect()
    }

    fn moved(x: u16) -> InputMsg {
        InputMsg::MouseMove {
            monitor: 2,
            x,
            y: 0,
        }
    }

    #[test]
    fn every_protocol_key_has_one_winit_key() {
        let mapped: HashSet<KeyCode> = MAPPED.iter().map(|&key| key_code(key).unwrap()).collect();
        assert_eq!(mapped.len(), MAPPED.len(), "two winit keys map to one key");
        assert_eq!(
            mapped.len(),
            KeyCode::ALL.len(),
            "a protocol key has no winit key"
        );
        assert_eq!(key_code(WinitKey::SuperLeft), Some(KeyCode::MetaLeft));
        assert_eq!(key_code(WinitKey::IntlRo), Some(KeyCode::IntlRo));
        assert_eq!(key_code(WinitKey::Fn), None);
    }

    #[test]
    fn moves_are_paced_and_flushed_before_clicks() {
        let (mut input, mut rx) = input();
        let start = Instant::now();
        input.move_to(1, 0, start);
        input.move_to(2, 0, start + Duration::from_millis(1));
        input.move_to(3, 0, start + Duration::from_millis(2));
        assert_eq!(drain(&mut rx), [moved(1)]);
        // The click carries the latest position first.
        input.button(MouseButton::Left, true, start + Duration::from_millis(3));
        assert_eq!(
            drain(&mut rx),
            [
                moved(3),
                InputMsg::MouseButton {
                    button: MouseButton::Left,
                    down: true
                }
            ]
        );
        // A waiting move goes out on the tick once due.
        input.move_to(4, 0, start + Duration::from_millis(4));
        assert!(drain(&mut rx).is_empty());
        let next = input.tick(start + Duration::from_millis(5)).unwrap();
        assert_eq!(next, start + Duration::from_millis(7));
        input.tick(next);
        assert_eq!(drain(&mut rx), [moved(4)]);
    }

    #[test]
    fn held_keeps_the_agent_informed_and_release_all_clears() {
        let (mut input, mut rx) = input();
        let start = Instant::now();
        input.key(KeyCode::ShiftLeft, true, start);
        assert_eq!(input.tick(start), Some(start + HELD_PERIOD));
        input.tick(start + HELD_PERIOD);
        assert_eq!(
            drain(&mut rx),
            [
                InputMsg::Key {
                    code: KeyCode::ShiftLeft,
                    down: true
                },
                InputMsg::Held
            ]
        );
        input.release_all(start + HELD_PERIOD);
        assert_eq!(drain(&mut rx), [InputMsg::ReleaseAll]);
        assert_eq!(input.tick(start + HELD_PERIOD * 3), None);
        // Stray releases are not sent; nothing is held, so drop is quiet.
        input.key(KeyCode::ShiftLeft, false, start);
        drop(input);
        assert!(drain(&mut rx).is_empty());
    }

    #[test]
    fn dropping_releases_what_is_held() {
        let (mut input, mut rx) = input();
        input.button(MouseButton::Right, true, Instant::now());
        drop(input);
        assert_eq!(drain(&mut rx).last(), Some(&InputMsg::ReleaseAll));
    }

    #[test]
    fn touchpad_scrolling_keeps_the_remainder() {
        let (mut input, mut rx) = input();
        let now = Instant::now();
        input.wheel_pixels(0.0, 20.0, now); // 40 units
        input.wheel_pixels(0.0, 20.0, now); // 80
        assert_eq!(
            drain(&mut rx),
            [
                InputMsg::Wheel { dx: 0, dy: 40 },
                InputMsg::Wheel { dx: 0, dy: 40 }
            ]
        );
        input.wheel_notches(0.0, -1.0, now);
        assert_eq!(drain(&mut rx), [InputMsg::Wheel { dx: 0, dy: -120 }]);
        input.wheel_pixels(0.1, 0.0, now); // 0.2 units: kept for later
        assert!(drain(&mut rx).is_empty());
    }

    #[test]
    fn coordinates_follow_the_letterbox() {
        let rect = PictureRect {
            x: 40.0,
            y: 0.0,
            width: 1920.0,
            height: 1080.0,
            scale: 1.0,
        };
        assert_eq!(picture_coords((40.0, 0.0), rect, false), Some((0, 0)));
        assert_eq!(
            picture_coords((1000.0, 540.0), rect, false),
            Some((32768, 32768))
        );
        assert_eq!(
            picture_coords((1959.999, 1079.999), rect, false),
            Some((65535, 65535))
        );
        assert_eq!(picture_coords((39.0, 10.0), rect, false), None);
        assert_eq!(picture_coords((1960.0, 10.0), rect, false), None);
        // During a drag the position is pinned to the edge.
        assert_eq!(picture_coords((0.0, -50.0), rect, true), Some((0, 0)));
        assert_eq!(
            picture_coords((5000.0, 5000.0), rect, true),
            Some((65535, 65535))
        );
    }
}
