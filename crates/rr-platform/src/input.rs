//! Input injection (blueprint v2 §3, §8.7): keys and mouse from the Viewer
//! replayed on this machine.
//!
//! Backends: `SendInput` on Windows; on Linux, XTest (X11) or the
//! xdg-desktop-portal RemoteDesktop interface (Wayland), which shares its
//! session with the screen capture (see [`crate::capture::open_screen`]).
//!
//! [`Injector`] sits on top of a backend and remembers what is pressed, so
//! that [`Injector::release_all`] (also run on drop) never leaves a key or
//! button down on the Agent.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, PoisonError};

pub use rr_proto::{KeyCode, MouseButton};

use crate::capture::Monitor;

/// Input failures.
#[derive(Debug, thiserror::Error)]
pub enum InputError {
    /// No backend for this platform or session type.
    #[error("input injection is not supported here: {0}")]
    Unsupported(&'static str),
    /// The local user did not allow remote control in the system dialog.
    #[error("the local user did not allow remote control")]
    Denied,
    /// An OS call failed.
    #[error("{context} failed: {message} ({code:#010x})")]
    Os {
        /// The failing call.
        context: &'static str,
        /// OS error code, if any.
        code: u32,
        /// OS error text.
        message: String,
    },
}

/// Where the captured monitor sits on the desktop, in the coordinates
/// input uses (virtual-desktop pixels on Windows, root-window pixels on
/// X11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Area {
    /// Left edge.
    pub left: i32,
    /// Top edge.
    pub top: i32,
    /// Width in pixels (at least 1).
    pub width: u32,
    /// Height in pixels (at least 1).
    pub height: u32,
}

impl Area {
    /// The area a monitor covers; `None` while its size is unknown.
    #[must_use]
    pub const fn of(monitor: &Monitor) -> Option<Self> {
        if monitor.width == 0 || monitor.height == 0 {
            return None;
        }
        Some(Self {
            left: monitor.left,
            top: monitor.top,
            width: monitor.width,
            height: monitor.height,
        })
    }

    /// The desktop pixel at protocol coordinates (`0..=65535` across the
    /// monitor): `x / 65536` of the way from the left edge, so every
    /// coordinate lands inside the monitor.
    #[must_use]
    pub fn pixel(&self, x: u16, y: u16) -> (i32, i32) {
        (
            offset(self.left, self.width, x),
            offset(self.top, self.height, y),
        )
    }

    /// Protocol coordinates of desktop pixel (`x`, `y`), aimed at the
    /// pixel's center so that [`Area::pixel`] maps them back to it; `None`
    /// outside the monitor.
    #[must_use]
    pub fn coords(&self, x: i32, y: i32) -> Option<(u16, u16)> {
        Some((
            coord(self.left, self.width, x)?,
            coord(self.top, self.height, y)?,
        ))
    }
}

fn coord(origin: i32, size: u32, pixel: i32) -> Option<u16> {
    let offset = u64::try_from(i64::from(pixel) - i64::from(origin)).ok()?;
    let size = u64::from(size);
    if offset >= size {
        return None;
    }
    let value = ((2 * offset + 1) << 15) / size;
    Some(u16::try_from(value).unwrap_or(u16::MAX))
}

fn offset(origin: i32, size: u32, coord: u16) -> i32 {
    let step = u64::from(size).saturating_mul(u64::from(coord)) >> 16;
    let step = i64::try_from(step).unwrap_or(i64::MAX);
    i32::try_from(i64::from(origin).saturating_add(step)).unwrap_or(i32::MAX)
}

/// The captured monitor's [`Area`], shared between the capture side (which
/// updates it when the monitor moves or changes resolution) and input.
#[derive(Debug, Clone, Default)]
pub struct SharedArea(Arc<Mutex<Option<Area>>>);

impl SharedArea {
    /// Records the current area.
    pub fn set(&self, area: Option<Area>) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = area;
    }

    /// The current area, if known.
    #[must_use]
    pub fn get(&self) -> Option<Area> {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Most wheel clicks one event turns into, so a forged huge delta cannot
/// keep the Agent busy.
const MAX_CLICKS: i32 = 30;

/// Turns wheel travel in 1/120-notch units into whole clicks for systems
/// that only know clicks (X11 buttons 4 to 7, the portal's discrete axis).
/// Smooth-scroll remainders are kept for the next event; turning the other
/// way drops them.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, Default)]
pub(crate) struct Notches {
    x: i32,
    y: i32,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl Notches {
    /// Adds travel and returns the whole clicks to inject now, with the
    /// signs of the input (`dy > 0` up, `dx > 0` right).
    pub(crate) fn add(&mut self, dx: i32, dy: i32) -> (i32, i32) {
        (Self::axis(&mut self.x, dx), Self::axis(&mut self.y, dy))
    }

    fn axis(rest: &mut i32, delta: i32) -> i32 {
        if rest.signum() * delta.signum() < 0 {
            *rest = 0;
        }
        let total = rest.saturating_add(delta);
        let clicks = total / i32::from(rr_proto::input::WHEEL_NOTCH);
        *rest = total % i32::from(rr_proto::input::WHEEL_NOTCH);
        clicks.clamp(-MAX_CLICKS, MAX_CLICKS)
    }
}

/// One way of injecting input. Implementations do not track state; use
/// [`Injector`].
pub trait InputBackend: Send {
    /// Presses or releases a key. Called again with `down` for an
    /// auto-repeat when [`InputBackend::repeats_by_itself`] is `false`.
    ///
    /// # Errors
    /// An OS failure.
    fn key(&mut self, key: KeyCode, down: bool) -> Result<(), InputError>;

    /// Moves the pointer to protocol coordinates on the captured monitor.
    ///
    /// # Errors
    /// An OS failure.
    fn move_to(&mut self, x: u16, y: u16) -> Result<(), InputError>;

    /// Presses or releases a button.
    ///
    /// # Errors
    /// An OS failure.
    fn button(&mut self, button: MouseButton, down: bool) -> Result<(), InputError>;

    /// Turns the wheel, in 1/120-notch units: `dy > 0` scrolls up,
    /// `dx > 0` scrolls right.
    ///
    /// # Errors
    /// An OS failure.
    fn wheel(&mut self, dx: i32, dy: i32) -> Result<(), InputError>;

    /// Whether this system repeats a held key by itself (the X server, or
    /// Wayland clients). Repeats from the Viewer are then dropped; Windows
    /// does not repeat injected keys, so there they are replayed.
    fn repeats_by_itself(&self) -> bool;

    /// A short description for logs, e.g. `SendInput`.
    fn name(&self) -> &'static str;
}

/// Injects through a backend and remembers what is pressed.
pub struct Injector {
    backend: Box<dyn InputBackend>,
    keys: BTreeSet<KeyCode>,
    buttons: BTreeSet<MouseButton>,
}

impl Injector {
    /// Wraps `backend`.
    #[must_use]
    pub fn new(backend: Box<dyn InputBackend>) -> Self {
        Self {
            backend,
            keys: BTreeSet::new(),
            buttons: BTreeSet::new(),
        }
    }

    /// The backend's name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.backend.name()
    }

    /// Presses or releases `key`. A press of a key already down is an
    /// auto-repeat; a release of a key that is not down is ignored.
    ///
    /// # Errors
    /// An OS failure.
    pub fn key(&mut self, key: KeyCode, down: bool) -> Result<(), InputError> {
        if down {
            if !self.keys.insert(key) && self.backend.repeats_by_itself() {
                return Ok(());
            }
        } else if !self.keys.remove(&key) {
            return Ok(());
        }
        self.backend.key(key, down)
    }

    /// Moves the pointer.
    ///
    /// # Errors
    /// An OS failure.
    pub fn move_to(&mut self, x: u16, y: u16) -> Result<(), InputError> {
        self.backend.move_to(x, y)
    }

    /// Presses or releases `button`; repeated presses and stray releases
    /// are ignored.
    ///
    /// # Errors
    /// An OS failure.
    pub fn button(&mut self, button: MouseButton, down: bool) -> Result<(), InputError> {
        let changed = if down {
            self.buttons.insert(button)
        } else {
            self.buttons.remove(&button)
        };
        if changed {
            self.backend.button(button, down)
        } else {
            Ok(())
        }
    }

    /// Turns the wheel (see [`InputBackend::wheel`]).
    ///
    /// # Errors
    /// An OS failure.
    pub fn wheel(&mut self, dx: i32, dy: i32) -> Result<(), InputError> {
        if dx == 0 && dy == 0 {
            return Ok(());
        }
        self.backend.wheel(dx, dy)
    }

    /// Whether any key or button is down.
    #[must_use]
    pub fn holding(&self) -> bool {
        !self.keys.is_empty() || !self.buttons.is_empty()
    }

    /// Releases every button, then every key (other keys before
    /// modifiers, so no shortcut fires on the way). Keeps going after a
    /// failure and returns the first one.
    ///
    /// # Errors
    /// The first OS failure.
    pub fn release_all(&mut self) -> Result<(), InputError> {
        let mut first = Ok(());
        for button in std::mem::take(&mut self.buttons) {
            let result = self.backend.button(button, false);
            if first.is_ok() {
                first = result;
            }
        }
        let keys = std::mem::take(&mut self.keys);
        let (modifiers, others): (Vec<_>, Vec<_>) =
            keys.into_iter().partition(|key| key.is_modifier());
        for key in others.into_iter().chain(modifiers) {
            let result = self.backend.key(key, false);
            if first.is_ok() {
                first = result;
            }
        }
        first
    }
}

impl Drop for Injector {
    fn drop(&mut self) {
        let _ = self.release_all();
    }
}

impl std::fmt::Debug for Injector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Injector")
            .field("backend", &self.backend.name())
            .field("keys", &self.keys)
            .field("buttons", &self.buttons)
            .finish()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    /// Records every call.
    #[derive(Clone, Default)]
    pub(crate) struct Recorder {
        pub(crate) calls: Arc<Mutex<Vec<String>>>,
        pub(crate) repeats: bool,
    }

    impl InputBackend for Recorder {
        fn key(&mut self, key: KeyCode, down: bool) -> Result<(), InputError> {
            self.calls.lock().unwrap().push(format!(
                "key {} {}",
                key.name(),
                if down { "down" } else { "up" }
            ));
            Ok(())
        }
        fn move_to(&mut self, x: u16, y: u16) -> Result<(), InputError> {
            self.calls.lock().unwrap().push(format!("move {x} {y}"));
            Ok(())
        }
        fn button(&mut self, button: MouseButton, down: bool) -> Result<(), InputError> {
            self.calls.lock().unwrap().push(format!(
                "button {button:?} {}",
                if down { "down" } else { "up" }
            ));
            Ok(())
        }
        fn wheel(&mut self, dx: i32, dy: i32) -> Result<(), InputError> {
            self.calls.lock().unwrap().push(format!("wheel {dx} {dy}"));
            Ok(())
        }
        fn repeats_by_itself(&self) -> bool {
            self.repeats
        }
        fn name(&self) -> &'static str {
            "recorder"
        }
    }

    fn take(recorder: &Recorder) -> Vec<String> {
        std::mem::take(&mut *recorder.calls.lock().unwrap())
    }

    #[test]
    fn release_all_frees_everything_once() {
        let recorder = Recorder::default();
        let mut injector = Injector::new(Box::new(recorder.clone()));
        injector.key(KeyCode::ControlLeft, true).unwrap();
        injector.key(KeyCode::KeyC, true).unwrap();
        injector.button(MouseButton::Left, true).unwrap();
        assert!(injector.holding());
        take(&recorder);
        injector.release_all().unwrap();
        assert_eq!(
            take(&recorder),
            ["button Left up", "key KeyC up", "key ControlLeft up"]
        );
        assert!(!injector.holding());
        // Nothing is left for a second release or for drop.
        injector.release_all().unwrap();
        drop(injector);
        assert!(take(&recorder).is_empty());
    }

    #[test]
    fn dropping_releases_held_keys() {
        let recorder = Recorder::default();
        let mut injector = Injector::new(Box::new(recorder.clone()));
        injector.key(KeyCode::ShiftLeft, true).unwrap();
        drop(injector);
        assert_eq!(take(&recorder), ["key ShiftLeft down", "key ShiftLeft up"]);
    }

    #[test]
    fn repeats_follow_the_backend() {
        // Windows: repeats are replayed.
        let recorder = Recorder::default();
        let mut injector = Injector::new(Box::new(recorder.clone()));
        injector.key(KeyCode::KeyA, true).unwrap();
        injector.key(KeyCode::KeyA, true).unwrap();
        injector.key(KeyCode::KeyA, false).unwrap();
        injector.key(KeyCode::KeyA, false).unwrap();
        assert_eq!(
            take(&recorder),
            ["key KeyA down", "key KeyA down", "key KeyA up"]
        );
        // X11 / Wayland: the system repeats, so repeats are dropped.
        let recorder = Recorder {
            repeats: true,
            ..Recorder::default()
        };
        let mut injector = Injector::new(Box::new(recorder.clone()));
        injector.key(KeyCode::KeyA, true).unwrap();
        injector.key(KeyCode::KeyA, true).unwrap();
        injector.key(KeyCode::KeyA, false).unwrap();
        assert_eq!(take(&recorder), ["key KeyA down", "key KeyA up"]);
    }

    #[test]
    fn buttons_ignore_repeats_and_stray_releases() {
        let recorder = Recorder::default();
        let mut injector = Injector::new(Box::new(recorder.clone()));
        injector.button(MouseButton::Right, false).unwrap();
        injector.button(MouseButton::Right, true).unwrap();
        injector.button(MouseButton::Right, true).unwrap();
        injector.button(MouseButton::Right, false).unwrap();
        injector.wheel(0, 0).unwrap();
        assert_eq!(take(&recorder), ["button Right down", "button Right up"]);
    }

    #[test]
    fn wheel_travel_becomes_whole_clicks() {
        let mut notches = Notches::default();
        // Two notches up, one to the left.
        assert_eq!(notches.add(-120, 240), (-1, 2));
        // Smooth scrolling: 40 + 40 + 40 is one click.
        assert_eq!(notches.add(0, 40), (0, 0));
        assert_eq!(notches.add(0, 40), (0, 0));
        assert_eq!(notches.add(0, 40), (0, 1));
        // Turning the other way forgets the remainder.
        assert_eq!(notches.add(0, 100), (0, 0));
        assert_eq!(notches.add(0, -120), (0, -1));
        // Huge deltas are capped.
        assert_eq!(notches.add(i32::from(i16::MAX), 0), (MAX_CLICKS, 0));
    }

    #[test]
    fn coordinates_cover_the_monitor() {
        let area = Area {
            left: -1920,
            top: 0,
            width: 1920,
            height: 1080,
        };
        assert_eq!(area.pixel(0, 0), (-1920, 0));
        assert_eq!(area.pixel(u16::MAX, u16::MAX), (-1, 1079));
        assert_eq!(area.pixel(32768, 32768), (-960, 540));
        let tiny = Area {
            left: 10,
            top: 20,
            width: 1,
            height: 1,
        };
        assert_eq!(tiny.pixel(u16::MAX, 0), (10, 20));
    }

    #[test]
    fn pixels_and_coordinates_round_trip() {
        for (left, width) in [(0, 1920), (-1920, 1920), (100, 1), (0, 7680), (0, 32_768)] {
            let area = Area {
                left,
                top: left,
                width,
                height: width,
            };
            for offset in 0..i32::try_from(width).unwrap() {
                let pixel = left + offset;
                let (x, y) = area.coords(pixel, pixel).unwrap();
                assert_eq!(
                    area.pixel(x, y),
                    (pixel, pixel),
                    "left {left} width {width}"
                );
            }
            let end = left + i32::try_from(width).unwrap();
            assert_eq!(area.coords(left - 1, left), None);
            assert_eq!(area.coords(end, left), None);
        }
    }
}
