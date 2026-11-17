//! Input injection on X11 with the XTest extension (blueprint v2 §3,
//! §8.7).
//!
//! Keys are sent as X keycodes (evdev + 8), so the X server's keyboard
//! layout decides the character, as for a local keyboard. The pointer moves
//! in root-window pixels inside the captured monitor. The server repeats
//! held keys by itself, so repeats from the Viewer are dropped.

use x11rb::connection::{Connection as _, RequestConnection as _};
use x11rb::protocol::Event;
use x11rb::protocol::xproto;
use x11rb::protocol::xtest::{self, ConnectionExt as _};
use x11rb::rust_connection::RustConnection;

use crate::input::{InputBackend, InputError, KeyCode, MouseButton, Notches, SharedArea};
use crate::keymap;

/// X keycodes are evdev codes shifted by 8.
const KEYCODE_OFFSET: u16 = 8;

/// Core pointer buttons for the wheel: up, down, left, right.
const WHEEL_UP: u8 = 4;
const WHEEL_DOWN: u8 = 5;
const WHEEL_LEFT: u8 = 6;
const WHEEL_RIGHT: u8 = 7;

fn os_error(context: &'static str, err: impl std::fmt::Display) -> InputError {
    InputError::Os {
        context,
        code: 0,
        message: err.to_string(),
    }
}

/// Injects with XTest on the display named by `$DISPLAY`.
pub(crate) struct XTestBackend {
    conn: RustConnection,
    root: xproto::Window,
    area: SharedArea,
    notches: Notches,
}

impl XTestBackend {
    /// Connects and checks for XTest.
    pub(crate) fn open(area: SharedArea) -> Result<Self, InputError> {
        let (conn, screen) =
            x11rb::connect(None).map_err(|err| os_error("connecting to the X server", err))?;
        let root = conn
            .setup()
            .roots
            .get(screen)
            .map(|screen| screen.root)
            .ok_or_else(|| os_error("connecting to the X server", "no such screen"))?;
        let present = conn
            .extension_information(xtest::X11_EXTENSION_NAME)
            .map_err(|err| os_error("QueryExtension", err))?
            .is_some();
        if !present {
            return Err(InputError::Unsupported(
                "the X server has no XTest extension",
            ));
        }
        conn.xtest_get_version(2, 2)
            .map_err(|err| os_error("XTestGetVersion", err))?
            .reply()
            .map_err(|err| os_error("XTestGetVersion", err))?;
        // Keep injecting while another client grabs the server.
        conn.xtest_grab_control(true)
            .map_err(|err| os_error("XTestGrabControl", err))?;
        conn.flush()
            .map_err(|err| os_error("XTestGrabControl", err))?;
        Ok(Self {
            conn,
            root,
            area,
            notches: Notches::default(),
        })
    }

    /// Queues one fake event.
    fn fake(&self, kind: u8, detail: u8, x: i16, y: i16) -> Result<(), InputError> {
        self.conn
            .xtest_fake_input(kind, detail, x11rb::CURRENT_TIME, self.root, x, y, 0)
            .map(|_| ())
            .map_err(|err| os_error("XTestFakeInput", err))
    }

    /// Sends what was queued and surfaces errors the server reported for
    /// earlier requests (they arrive as events on this connection).
    fn flush(&self) -> Result<(), InputError> {
        self.conn
            .flush()
            .map_err(|err| os_error("XTestFakeInput", err))?;
        let mut first = Ok(());
        while let Some(event) = self
            .conn
            .poll_for_event()
            .map_err(|err| os_error("XTestFakeInput", err))?
        {
            if let Event::Error(err) = event
                && first.is_ok()
            {
                first = Err(os_error("XTestFakeInput", format!("{:?}", err.error_kind)));
            }
        }
        first
    }

    fn click(&self, button: u8, times: u32) -> Result<(), InputError> {
        for _ in 0..times {
            self.fake(xproto::BUTTON_PRESS_EVENT, button, 0, 0)?;
            self.fake(xproto::BUTTON_RELEASE_EVENT, button, 0, 0)?;
        }
        Ok(())
    }
}

/// A root-window coordinate, clamped to X's 16-bit range.
fn coord(value: i32) -> i16 {
    i16::try_from(value.clamp(i32::from(i16::MIN), i32::from(i16::MAX))).unwrap_or(0)
}

const fn button_number(button: MouseButton) -> u8 {
    match button {
        MouseButton::Left => 1,
        MouseButton::Middle => 2,
        MouseButton::Right => 3,
        MouseButton::Back => 8,
        MouseButton::Forward => 9,
    }
}

impl InputBackend for XTestBackend {
    fn key(&mut self, key: KeyCode, down: bool) -> Result<(), InputError> {
        let Some(code) = keymap::evdev(key)
            .and_then(|code| code.checked_add(KEYCODE_OFFSET))
            .and_then(|code| u8::try_from(code).ok())
        else {
            return Ok(());
        };
        let kind = if down {
            xproto::KEY_PRESS_EVENT
        } else {
            xproto::KEY_RELEASE_EVENT
        };
        self.fake(kind, code, 0, 0)?;
        self.flush()
    }

    fn move_to(&mut self, x: u16, y: u16) -> Result<(), InputError> {
        let Some(area) = self.area.get() else {
            return Ok(());
        };
        let (px, py) = area.pixel(x, y);
        // Detail 0: absolute coordinates on `root`.
        self.fake(xproto::MOTION_NOTIFY_EVENT, 0, coord(px), coord(py))?;
        self.flush()
    }

    fn button(&mut self, button: MouseButton, down: bool) -> Result<(), InputError> {
        let kind = if down {
            xproto::BUTTON_PRESS_EVENT
        } else {
            xproto::BUTTON_RELEASE_EVENT
        };
        self.fake(kind, button_number(button), 0, 0)?;
        self.flush()
    }

    fn wheel(&mut self, dx: i32, dy: i32) -> Result<(), InputError> {
        let (x, y) = self.notches.add(dx, dy);
        if x == 0 && y == 0 {
            return Ok(());
        }
        let vertical = if y > 0 { WHEEL_UP } else { WHEEL_DOWN };
        self.click(vertical, y.unsigned_abs())?;
        let horizontal = if x > 0 { WHEEL_RIGHT } else { WHEEL_LEFT };
        self.click(horizontal, x.unsigned_abs())?;
        self.flush()
    }

    fn repeats_by_itself(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        "XTest"
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use x11rb::protocol::xproto::{
        ConnectionExt as _, CreateWindowAux, EventMask, InputFocus, WindowClass,
    };

    use super::*;
    use crate::input::Area;

    /// Run under Xvfb: `xvfb-run -a cargo test -- --ignored`.
    #[test]
    #[ignore = "needs an X server with XTest"]
    fn injected_events_reach_a_window() {
        let (conn, screen) = crate::linux::x11::connect().unwrap();
        let window = conn.generate_id().unwrap();
        let mask = EventMask::KEY_PRESS
            | EventMask::KEY_RELEASE
            | EventMask::BUTTON_PRESS
            | EventMask::BUTTON_RELEASE
            | EventMask::POINTER_MOTION;
        conn.create_window(
            x11rb::COPY_DEPTH_FROM_PARENT,
            window,
            screen.root,
            100,
            50,
            200,
            100,
            0,
            WindowClass::INPUT_OUTPUT,
            x11rb::COPY_FROM_PARENT,
            &CreateWindowAux::new().event_mask(mask).override_redirect(1),
        )
        .unwrap();
        conn.map_window(window).unwrap();
        conn.set_input_focus(InputFocus::PARENT, window, x11rb::CURRENT_TIME)
            .unwrap();
        conn.get_input_focus().unwrap().reply().unwrap();

        let area = SharedArea::default();
        area.set(Some(Area {
            left: 0,
            top: 0,
            width: u32::from(screen.width_in_pixels),
            height: u32::from(screen.height_in_pixels),
        }));
        let (x, y) = area.get().unwrap().coords(150, 80).unwrap();
        let mut backend = XTestBackend::open(area).unwrap();
        backend.move_to(x, y).unwrap();
        backend.button(MouseButton::Left, true).unwrap();
        backend.button(MouseButton::Left, false).unwrap();
        backend.key(KeyCode::KeyA, true).unwrap();
        backend.key(KeyCode::KeyA, false).unwrap();
        // Two half notches make one click up (button 4).
        backend.wheel(0, 60).unwrap();
        backend.wheel(0, 60).unwrap();

        let mut seen = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline && seen.len() < 7 {
            match conn.poll_for_event().unwrap() {
                Some(Event::MotionNotify(event)) => {
                    seen.push(format!("motion {} {}", event.event_x, event.event_y));
                }
                Some(Event::ButtonPress(event)) => seen.push(format!("press {}", event.detail)),
                Some(Event::ButtonRelease(event)) => {
                    seen.push(format!("release {}", event.detail));
                }
                Some(Event::KeyPress(event)) => seen.push(format!("key down {}", event.detail)),
                Some(Event::KeyRelease(event)) => seen.push(format!("key up {}", event.detail)),
                Some(_) => {}
                None => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        // KeyA is evdev 30, X keycode 38. The window is at (100, 50).
        assert_eq!(
            seen,
            [
                "motion 50 30",
                "press 1",
                "release 1",
                "key down 38",
                "key up 38",
                "press 4",
                "release 4",
            ]
        );
    }

    #[test]
    fn coordinates_fit_sixteen_bits() {
        assert_eq!(coord(0), 0);
        assert_eq!(coord(-70_000), i16::MIN);
        assert_eq!(coord(70_000), i16::MAX);
    }

    #[test]
    fn every_key_with_an_evdev_code_has_an_x_keycode() {
        for &key in KeyCode::ALL {
            if let Some(code) = keymap::evdev(key) {
                assert!(
                    u8::try_from(code + KEYCODE_OFFSET).is_ok(),
                    "{}",
                    key.name()
                );
            }
        }
    }
}
