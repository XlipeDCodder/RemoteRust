//! The kill-switch hotkey on X11 (blueprint v2 §7.6): XInput 2 raw key
//! events from every keyboard except the XTEST ones.
//!
//! Raw events reach the root window whatever has the focus or a grab, and
//! name the slave device that produced them (`sourceid`). XTest input,
//! including the Agent's own remote input, comes from the "Virtual core
//! XTEST keyboard" slave, so leaving that device out leaves exactly the
//! physical keyboards. Nothing is grabbed: the keys still reach the
//! focused window, as they must (a grab would fire for injected keys too).

use std::collections::HashSet;
use std::os::fd::AsFd as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use rustix::event::{PollFd, PollFlags};
use x11rb::connection::{Connection as _, RequestConnection as _};
use x11rb::protocol::Event;
use x11rb::protocol::xinput::{self, ConnectionExt as _, DeviceId, EventMask, XIEventMask};
use x11rb::rust_connection::RustConnection;

use crate::input::InputError;
use crate::keymap;
use crate::killswitch::{Detector, Verdict};

/// `XIAllDevices` and `XIAllMasterDevices`.
const ALL_DEVICES: DeviceId = 0;
const ALL_MASTER_DEVICES: DeviceId = 1;

/// How often the watcher thread checks whether it should stop.
const STOP_POLL: Duration = Duration::from_millis(100);

fn os_error(context: &'static str, err: impl std::fmt::Display) -> InputError {
    InputError::Os {
        context,
        code: 0,
        message: err.to_string(),
    }
}

/// The running watcher; stopped on drop.
pub(crate) struct Watch {
    stop: Arc<AtomicBool>,
    /// Injected (XTEST) key events seen and ignored, for tests.
    #[cfg_attr(not(test), allow(dead_code))]
    ignored: Arc<AtomicU64>,
    thread: Option<JoinHandle<()>>,
}

impl Watch {
    #[cfg(test)]
    fn ignored(&self) -> u64 {
        self.ignored.load(Ordering::SeqCst)
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Starts watching `$DISPLAY`'s keyboards on a new thread.
pub(crate) fn watch(
    detector: Detector,
    on_trigger: impl Fn() + Send + 'static,
) -> Result<Watch, InputError> {
    let (conn, screen) =
        x11rb::connect(None).map_err(|err| os_error("connecting to the X server", err))?;
    let root = conn
        .setup()
        .roots
        .get(screen)
        .map(|screen| screen.root)
        .ok_or_else(|| os_error("connecting to the X server", "no such screen"))?;
    if conn
        .extension_information(xinput::X11_EXTENSION_NAME)
        .map_err(|err| os_error("QueryExtension", err))?
        .is_none()
    {
        return Err(InputError::Unsupported(
            "the X server has no XInput extension",
        ));
    }
    let version = conn
        .xinput_xi_query_version(2, 2)
        .map_err(|err| os_error("XIQueryVersion", err))?
        .reply()
        .map_err(|err| os_error("XIQueryVersion", err))?;
    if version.major_version < 2 {
        return Err(InputError::Unsupported("the X server has no XInput 2"));
    }
    conn.xinput_xi_select_events(
        root,
        &[
            EventMask {
                deviceid: ALL_DEVICES,
                mask: vec![XIEventMask::HIERARCHY],
            },
            // Through the master keyboard: each key once, with the slave
            // that produced it as `sourceid`.
            EventMask {
                deviceid: ALL_MASTER_DEVICES,
                mask: vec![XIEventMask::RAW_KEY_PRESS | XIEventMask::RAW_KEY_RELEASE],
            },
        ],
    )
    .map_err(|err| os_error("XISelectEvents", err))?
    .check()
    .map_err(|err| os_error("XISelectEvents", err))?;
    let mut filter = Filter {
        injected: xtest_devices(&conn)?,
        detector,
    };

    let stop = Arc::new(AtomicBool::new(false));
    let ignored = Arc::new(AtomicU64::new(0));
    let thread = std::thread::Builder::new()
        .name("rr-killswitch".to_owned())
        .spawn({
            let stop = Arc::clone(&stop);
            let ignored = Arc::clone(&ignored);
            move || {
                if let Err(err) = run(&conn, &mut filter, &on_trigger, &stop, &ignored) {
                    tracing_free_report(&err);
                }
            }
        })
        .map_err(|err| os_error("starting the kill-switch thread", err))?;
    Ok(Watch {
        stop,
        ignored,
        thread: Some(thread),
    })
}

/// This crate does not log; the failure is visible as a kill switch that
/// no longer fires, and on stderr.
fn tracing_free_report(err: &InputError) {
    eprintln!("RustRemote: the kill-switch hotkey stopped working: {err}");
}

/// The XTEST slave devices, whose events are injected.
fn xtest_devices(conn: &RustConnection) -> Result<HashSet<DeviceId>, InputError> {
    let reply = conn
        .xinput_xi_query_device(ALL_DEVICES)
        .map_err(|err| os_error("XIQueryDevice", err))?
        .reply()
        .map_err(|err| os_error("XIQueryDevice", err))?;
    Ok(reply
        .infos
        .iter()
        .filter(|info| is_xtest(&info.name))
        .map(|info| info.deviceid)
        .collect())
}

fn is_xtest(name: &[u8]) -> bool {
    name.windows(5).any(|part| part == b"XTEST")
}

/// Turns raw events into physical key events for the detector.
struct Filter {
    injected: HashSet<DeviceId>,
    detector: Detector,
}

impl Filter {
    /// `None` for injected or unknown keys; else the detector's verdict.
    fn on_raw_key(&mut self, sourceid: DeviceId, keycode: u32, down: bool) -> Option<Verdict> {
        if self.injected.contains(&sourceid) {
            return None;
        }
        let evdev = u16::try_from(keycode.checked_sub(8)?).ok()?;
        let key = keymap::from_evdev(evdev)?;
        Some(self.detector.on_key(key, down))
    }
}

fn run(
    conn: &RustConnection,
    filter: &mut Filter,
    on_trigger: &dyn Fn(),
    stop: &AtomicBool,
    ignored: &AtomicU64,
) -> Result<(), InputError> {
    while !stop.load(Ordering::Relaxed) {
        while let Some(event) = conn
            .poll_for_event()
            .map_err(|err| os_error("reading X events", err))?
        {
            let (raw, down) = match event {
                Event::XinputRawKeyPress(raw) => (raw, true),
                Event::XinputRawKeyRelease(raw) => (raw, false),
                Event::XinputHierarchy(_) => {
                    // A keyboard was plugged in or removed.
                    filter.injected = xtest_devices(conn)?;
                    continue;
                }
                _ => continue,
            };
            match filter.on_raw_key(raw.sourceid, raw.detail, down) {
                Some(Verdict::Fired) => on_trigger(),
                Some(Verdict::Pass | Verdict::Swallow) => {}
                None => {
                    ignored.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        let Ok(timeout) = STOP_POLL.try_into() else {
            continue;
        };
        let mut fds = [PollFd::from_borrowed_fd(
            conn.stream().as_fd(),
            PollFlags::IN,
        )];
        match rustix::event::poll(&mut fds, Some(&timeout)) {
            Ok(_) | Err(rustix::io::Errno::INTR) => {}
            Err(err) => return Err(os_error("poll", err)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Instant;

    use super::*;
    use crate::input::{InputBackend as _, KeyCode, SharedArea};
    use crate::killswitch::Hotkey;

    fn filter() -> Filter {
        Filter {
            injected: HashSet::from([7]),
            detector: Detector::new(Hotkey::DEFAULT),
        }
    }

    // X keycodes (evdev + 8) of Ctrl, Alt, Shift (left) and F12.
    const COMBO: [u32; 4] = [37, 64, 50, 96];

    #[test]
    fn physical_keyboards_fire_and_xtest_does_not() {
        let mut physical = filter();
        let verdicts: Vec<_> = COMBO
            .iter()
            .map(|code| physical.on_raw_key(12, *code, true))
            .collect();
        assert_eq!(
            verdicts,
            [
                Some(Verdict::Pass),
                Some(Verdict::Pass),
                Some(Verdict::Pass),
                Some(Verdict::Fired)
            ]
        );

        let mut injected = filter();
        for code in COMBO {
            assert_eq!(injected.on_raw_key(7, code, true), None);
        }
        // Injected modifiers held do not complete a physical F12 either.
        assert_eq!(injected.on_raw_key(12, 96, true), Some(Verdict::Pass));
    }

    #[test]
    fn recognizes_xtest_device_names() {
        assert!(is_xtest(b"Virtual core XTEST keyboard"));
        assert!(is_xtest(b"Virtual core XTEST pointer"));
        assert!(!is_xtest(b"AT Translated Set 2 keyboard"));
        assert!(!is_xtest(b"Virtual core keyboard"));
    }

    /// Run under Xvfb: `xvfb-run -a cargo test -- --ignored`. Xvfb has no
    /// physical keyboard to press the hotkey on; this checks the watcher
    /// sees XTest keys, and ignores them.
    #[test]
    #[ignore = "needs an X server with XInput 2 and XTest"]
    fn xtest_hotkey_is_seen_but_ignored() {
        let fired = Arc::new(Mutex::new(0_u32));
        let count = Arc::clone(&fired);
        let watch = watch(Detector::new(Hotkey::DEFAULT), move || {
            *count.lock().unwrap() += 1;
        })
        .unwrap();
        let mut backend =
            crate::linux::x11_input::XTestBackend::open(SharedArea::default()).unwrap();
        let combo = [
            KeyCode::ControlLeft,
            KeyCode::AltLeft,
            KeyCode::ShiftLeft,
            KeyCode::F12,
        ];
        for key in combo {
            backend.key(key, true).unwrap();
        }
        for key in combo.iter().rev() {
            backend.key(*key, false).unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while watch.ignored() < 8 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(watch.ignored(), 8, "every injected key seen");
        assert_eq!(*fired.lock().unwrap(), 0);
    }
}
