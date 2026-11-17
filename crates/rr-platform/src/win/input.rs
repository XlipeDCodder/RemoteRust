//! Input injection with `SendInput` (blueprint v2 §3, §8.7).
//!
//! Keys are injected by scan code, so the active keyboard layout of the
//! focused window decides the character, exactly as for the local
//! keyboard. The pointer moves in absolute virtual-desktop coordinates;
//! the Agent is per-monitor DPI aware, so everything is in physical pixels.
//!
//! Windows does not auto-repeat injected keys: repeats from the Viewer are
//! replayed. Input cannot reach the secure desktop or windows of elevated
//! processes (UIPI) from an unprivileged Agent; `SendInput` then reports
//! zero events inserted.
#![allow(unsafe_code)] // FFI module: every block below is justified with `SAFETY:`.

use windows::Win32::UI::Input::KeyboardAndMouse::{
    INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBD_EVENT_FLAGS, KEYBDINPUT,
    KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, MOUSE_EVENT_FLAGS,
    MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
    MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN,
    MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_VIRTUALDESK, MOUSEEVENTF_WHEEL, MOUSEEVENTF_XDOWN,
    MOUSEEVENTF_XUP, MOUSEINPUT, SendInput, VIRTUAL_KEY,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
    XBUTTON1, XBUTTON2,
};

use crate::input::{InputBackend, InputError, KeyCode, MouseButton, SharedArea};
use crate::keymap;

/// Size of one `INPUT`, as `SendInput` wants it (40 bytes on x64).
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
const INPUT_SIZE: i32 = size_of::<INPUT>() as i32;

/// Injects with `SendInput` into the interactive desktop.
pub(crate) struct SendInputBackend {
    area: SharedArea,
}

impl SendInputBackend {
    pub(crate) const fn new(area: SharedArea) -> Self {
        Self { area }
    }
}

/// The virtual desktop: left, top, width, height.
fn virtual_desktop() -> (i32, i32, i32, i32) {
    // SAFETY: plain metric queries without side effects.
    let left = unsafe { GetSystemMetrics(SM_XVIRTUALSCREEN) };
    // SAFETY: as above.
    let top = unsafe { GetSystemMetrics(SM_YVIRTUALSCREEN) };
    // SAFETY: as above.
    let width = unsafe { GetSystemMetrics(SM_CXVIRTUALSCREEN) };
    // SAFETY: as above.
    let height = unsafe { GetSystemMetrics(SM_CYVIRTUALSCREEN) };
    (left, top, width, height)
}

/// `SendInput`'s 0..=65535 scale for desktop pixel `pixel` on an axis that
/// starts at `origin` and is `size` pixels long, aimed at the pixel's
/// center so that rounding either way lands on it.
fn normalized(pixel: i32, origin: i32, size: i32) -> i32 {
    let size = i64::from(size.max(1));
    let offset = (i64::from(pixel) - i64::from(origin)).clamp(0, size - 1);
    let value = ((2 * offset + 1) * 65_536) / (2 * size);
    i32::try_from(value.clamp(0, 65_535)).unwrap_or(65_535)
}

fn send(inputs: &[INPUT], context: &'static str) -> Result<(), InputError> {
    // SAFETY: `inputs` is a valid slice of initialized `INPUT`s and the
    // size argument is the size of one element.
    let sent = unsafe { SendInput(inputs, INPUT_SIZE) };
    if usize::try_from(sent).ok() == Some(inputs.len()) {
        Ok(())
    } else {
        let err = windows::core::Error::from_thread();
        Err(InputError::Os {
            context,
            code: err.code().0.cast_unsigned(),
            message: if err.message().is_empty() {
                "blocked (secure desktop or an elevated window)".to_owned()
            } else {
                err.message()
            },
        })
    }
}

fn mouse(flags: MOUSE_EVENT_FLAGS, dx: i32, dy: i32, data: u32) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx,
                dy,
                mouseData: data,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

impl InputBackend for SendInputBackend {
    fn key(&mut self, key: KeyCode, down: bool) -> Result<(), InputError> {
        let Some(win) = keymap::windows(key) else {
            return Ok(());
        };
        let mut flags = KEYBD_EVENT_FLAGS(0);
        if !down {
            flags |= KEYEVENTF_KEYUP;
        }
        if win.extended() {
            flags |= KEYEVENTF_EXTENDEDKEY;
        }
        let [_, scan] = win.scancode.to_be_bytes();
        let (vk, scan) = match win.vk {
            Some(vk) => (VIRTUAL_KEY(vk), u16::from(scan)),
            None => {
                flags |= KEYEVENTF_SCANCODE;
                (VIRTUAL_KEY(0), u16::from(scan))
            }
        };
        let input = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: vk,
                    wScan: scan,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        send(&[input], "SendInput (keyboard)")
    }

    fn move_to(&mut self, x: u16, y: u16) -> Result<(), InputError> {
        let Some(area) = self.area.get() else {
            return Ok(());
        };
        let (px, py) = area.pixel(x, y);
        let (left, top, width, height) = virtual_desktop();
        let input = mouse(
            MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
            normalized(px, left, width),
            normalized(py, top, height),
            0,
        );
        send(&[input], "SendInput (pointer)")
    }

    fn button(&mut self, button: MouseButton, down: bool) -> Result<(), InputError> {
        let (flags, data) = match (button, down) {
            (MouseButton::Left, true) => (MOUSEEVENTF_LEFTDOWN, 0),
            (MouseButton::Left, false) => (MOUSEEVENTF_LEFTUP, 0),
            (MouseButton::Right, true) => (MOUSEEVENTF_RIGHTDOWN, 0),
            (MouseButton::Right, false) => (MOUSEEVENTF_RIGHTUP, 0),
            (MouseButton::Middle, true) => (MOUSEEVENTF_MIDDLEDOWN, 0),
            (MouseButton::Middle, false) => (MOUSEEVENTF_MIDDLEUP, 0),
            (MouseButton::Back, true) => (MOUSEEVENTF_XDOWN, XBUTTON1),
            (MouseButton::Back, false) => (MOUSEEVENTF_XUP, XBUTTON1),
            (MouseButton::Forward, true) => (MOUSEEVENTF_XDOWN, XBUTTON2),
            (MouseButton::Forward, false) => (MOUSEEVENTF_XUP, XBUTTON2),
        };
        send(&[mouse(flags, 0, 0, u32::from(data))], "SendInput (button)")
    }

    fn wheel(&mut self, dx: i32, dy: i32) -> Result<(), InputError> {
        // Windows: positive WHEEL is away from the user (scroll up),
        // positive HWHEEL is to the right, as in the protocol.
        if dy != 0 {
            send(
                &[mouse(MOUSEEVENTF_WHEEL, 0, 0, dy.cast_unsigned())],
                "SendInput (wheel)",
            )?;
        }
        if dx != 0 {
            send(
                &[mouse(MOUSEEVENTF_HWHEEL, 0, 0, dx.cast_unsigned())],
                "SendInput (wheel)",
            )?;
        }
        Ok(())
    }

    fn repeats_by_itself(&self) -> bool {
        false
    }

    fn name(&self) -> &'static str {
        "SendInput"
    }
}

#[cfg(test)]
mod tests {
    use super::normalized;

    /// The pixel Windows picks for a normalized value (it scales by the
    /// desktop size and truncates).
    fn pixel_of(value: i32, origin: i32, size: i32) -> i32 {
        origin + i32::try_from(i64::from(value) * i64::from(size) / 65_536).unwrap()
    }

    #[test]
    fn every_pixel_round_trips() {
        for (origin, size) in [
            (0, 1920),
            (-1920, 3840),
            (0, 1080),
            (-1080, 2160),
            (0, 7680),
            (0, 1),
        ] {
            for offset in 0..size {
                let pixel = origin + offset;
                let value = normalized(pixel, origin, size);
                assert!((0..=65_535).contains(&value));
                assert_eq!(
                    pixel_of(value, origin, size),
                    pixel,
                    "origin {origin} size {size}"
                );
            }
        }
    }

    #[test]
    fn out_of_range_pixels_are_clamped() {
        assert_eq!(normalized(-5000, 0, 1920), normalized(0, 0, 1920));
        assert_eq!(normalized(99_999, 0, 1920), normalized(1919, 0, 1920));
    }

    /// Moves the real pointer over every monitor, then puts it back.
    #[test]
    #[ignore = "moves the pointer of the interactive desktop"]
    fn absolute_moves_land_on_the_pixel() {
        use windows::Win32::Foundation::POINT;
        use windows::Win32::UI::WindowsAndMessaging::{GetCursorPos, SetCursorPos};

        use super::SendInputBackend;
        use crate::input::{Area, InputBackend as _, SharedArea};

        let _ = crate::capture::set_dpi_aware();
        let mut saved = POINT::default();
        // SAFETY: valid out-parameter.
        unsafe { GetCursorPos(&raw mut saved) }.unwrap();
        let mut misses = Vec::new();
        for monitor in crate::capture::monitors().unwrap() {
            let area = SharedArea::default();
            area.set(Area::of(&monitor));
            let target = area.get().unwrap();
            let mut backend = SendInputBackend::new(area);
            let (width, height) = (
                i32::try_from(monitor.width).unwrap(),
                i32::try_from(monitor.height).unwrap(),
            );
            for (dx, dy) in [
                (0, 0),
                (width - 1, height - 1),
                (width / 2, height / 3),
                (7, height - 2),
            ] {
                let pixel = (monitor.left + dx, monitor.top + dy);
                let (x, y) = target.coords(pixel.0, pixel.1).unwrap();
                backend.move_to(x, y).unwrap();
                std::thread::sleep(std::time::Duration::from_millis(30));
                let mut now = POINT::default();
                // SAFETY: valid out-parameter.
                unsafe { GetCursorPos(&raw mut now) }.unwrap();
                if (now.x, now.y) != pixel {
                    misses.push((monitor.name.clone(), pixel, (now.x, now.y)));
                }
            }
        }
        // SAFETY: plain call.
        unsafe { SetCursorPos(saved.x, saved.y) }.unwrap();
        assert!(misses.is_empty(), "wanted vs got: {misses:?}");
    }
}
