//! Low-level keyboard hook for the Viewer (blueprint v2 §8.7).
//!
//! The hook runs on its own thread with its own message loop: Windows
//! holds every keystroke of the desktop until a low-level hook returns, so
//! it must never wait for the Viewer's render thread.
#![allow(unsafe_code)] // FFI module: every block below is justified with `SAFETY:`.

use std::cell::RefCell;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;

use windows::Win32::Foundation::{LPARAM, LRESULT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, GetMessageW, HC_ACTION, KBDLLHOOKSTRUCT, LLKHF_EXTENDED, LLKHF_INJECTED,
    LLKHF_UP, MSG, PM_NOREMOVE, PeekMessageW, PostThreadMessageW, SetWindowsHookExW,
    UnhookWindowsHookEx, WH_KEYBOARD_LL, WM_QUIT, WM_USER,
};

use crate::input::{InputError, KeyCode};
use crate::keymap;

/// Receives the keys the hook takes, on the hook thread.
pub(crate) type Forward = Box<dyn FnMut(KeyCode, bool) + Send>;

/// Events Windows synthesizes alongside real keys: the left Ctrl sent with
/// AltGr and the shifts some keyboards wrap around navigation keys. They
/// are taken (the local system must not see half of a pair) but never
/// forwarded: the remote system makes its own.
const FAKE_SCANCODES: [u16; 3] = [0x021D, 0xE02A, 0xE036];

fn hook_error(context: &'static str, err: &windows::core::Error) -> InputError {
    InputError::Os {
        context,
        code: err.code().0.cast_unsigned(),
        message: err.message(),
    }
}

/// What the hook thread knows.
struct State {
    active: Arc<AtomicBool>,
    forward: Forward,
    /// Keys whose press was taken: their release is taken too, so the
    /// local system never sees half a keystroke.
    taken: HashSet<u32>,
}

thread_local! {
    static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
}

/// The set-1 scan code of the event, `0xE0xx` for extended keys.
fn scancode(event: &KBDLLHOOKSTRUCT) -> u16 {
    let base = u16::try_from(event.scanCode).unwrap_or(0);
    if event.flags.0 & LLKHF_EXTENDED.0 != 0 {
        0xE000 | (base & 0xFF)
    } else {
        base
    }
}

/// Identifies a physical key between its press and its release.
fn key_id(event: &KBDLLHOOKSTRUCT) -> u32 {
    match scancode(event) {
        0 => 0x1_0000 | event.vkCode,
        scan => u32::from(scan),
    }
}

/// The protocol key for an event; `None` for synthesized and unknown keys.
fn translate(event: &KBDLLHOOKSTRUCT) -> Option<KeyCode> {
    let scan = scancode(event);
    if FAKE_SCANCODES.contains(&scan) {
        return None;
    }
    (scan != 0)
        .then(|| keymap::from_windows_scancode(scan))
        .flatten()
        .or_else(|| {
            u16::try_from(event.vkCode)
                .ok()
                .and_then(keymap::from_windows_vk)
        })
}

impl State {
    /// Whether to take the event away from the local system.
    fn on_event(&mut self, event: &KBDLLHOOKSTRUCT) -> bool {
        // Injected input (our own Agent on this machine, automation tools)
        // is left alone.
        if event.flags.0 & LLKHF_INJECTED.0 != 0 {
            return false;
        }
        let id = key_id(event);
        let key = translate(event);
        if event.flags.0 & LLKHF_UP.0 != 0 {
            if !self.taken.remove(&id) {
                return false;
            }
            if let Some(key) = key {
                (self.forward)(key, false);
            }
            return true;
        }
        let fake = FAKE_SCANCODES.contains(&scancode(event));
        if !self.active.load(Ordering::Relaxed) || (key.is_none() && !fake) {
            // A press while inactive belongs to the local system, and so
            // does its release.
            self.taken.remove(&id);
            return false;
        }
        self.taken.insert(id);
        if let Some(key) = key {
            (self.forward)(key, true);
        }
        true
    }
}

unsafe extern "system" fn hook_proc(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if u32::try_from(code).ok() == Some(HC_ACTION) {
        // SAFETY: for HC_ACTION, `lparam` points to the event's
        // KBDLLHOOKSTRUCT for the duration of this call.
        let event = unsafe { &*(lparam.0 as *const KBDLLHOOKSTRUCT) };
        let take = STATE.with(|state| {
            state
                .try_borrow_mut()
                .ok()
                .and_then(|mut state| state.as_mut().map(|state| state.on_event(event)))
                .unwrap_or(false)
        });
        if take {
            return LRESULT(1);
        }
    }
    // SAFETY: passes the event on unchanged, as hooks must.
    unsafe { CallNextHookEx(None, code, wparam, lparam) }
}

/// The installed hook; removed on drop.
pub(crate) struct Hook {
    thread_id: u32,
    thread: Option<JoinHandle<()>>,
}

/// Installs the hook on a new thread. Keys are taken only while `active`.
pub(crate) fn install(active: Arc<AtomicBool>, forward: Forward) -> Result<Hook, InputError> {
    let (ready, started) = mpsc::channel::<Result<u32, InputError>>();
    let thread = std::thread::Builder::new()
        .name("rr-kbhook".to_owned())
        .spawn(move || run(active, forward, &ready))
        .map_err(|err| InputError::Os {
            context: "starting the keyboard hook thread",
            code: 0,
            message: err.to_string(),
        })?;
    match started.recv() {
        Ok(Ok(thread_id)) => Ok(Hook {
            thread_id,
            thread: Some(thread),
        }),
        Ok(Err(err)) => {
            let _ = thread.join();
            Err(err)
        }
        Err(_) => {
            let _ = thread.join();
            Err(InputError::Os {
                context: "starting the keyboard hook thread",
                code: 0,
                message: "the thread ended early".to_owned(),
            })
        }
    }
}

fn run(active: Arc<AtomicBool>, forward: Forward, ready: &mpsc::Sender<Result<u32, InputError>>) {
    STATE.with(|state| {
        *state.borrow_mut() = Some(State {
            active,
            forward,
            taken: HashSet::new(),
        });
    });
    // SAFETY: the module handle of this executable; no preconditions.
    let module = match unsafe { GetModuleHandleW(None) } {
        Ok(module) => module,
        Err(err) => {
            let _ = ready.send(Err(hook_error("GetModuleHandleW", &err)));
            return;
        }
    };
    // SAFETY: `hook_proc` has the HOOKPROC signature and lives for the
    // whole program; this thread pumps messages below, as LL hooks need.
    let hook =
        match unsafe { SetWindowsHookExW(WH_KEYBOARD_LL, Some(hook_proc), Some(module.into()), 0) }
        {
            Ok(hook) => hook,
            Err(err) => {
                let _ = ready.send(Err(hook_error("SetWindowsHookExW", &err)));
                return;
            }
        };
    let mut msg = MSG::default();
    // Creates this thread's message queue, so the WM_QUIT from `Drop` can
    // never be posted before it exists.
    // SAFETY: `msg` is a valid out-parameter.
    let _ = unsafe { PeekMessageW(&raw mut msg, None, WM_USER, WM_USER, PM_NOREMOVE) };
    // SAFETY: no preconditions.
    let _ = ready.send(Ok(unsafe { GetCurrentThreadId() }));
    // The hook is called from inside GetMessageW; WM_QUIT (0) or an error
    // (-1) ends the loop.
    // SAFETY: `msg` is a valid out-parameter.
    while unsafe { GetMessageW(&raw mut msg, None, 0, 0) }.0 > 0 {}
    // SAFETY: the hook installed above, removed once.
    let _ = unsafe { UnhookWindowsHookEx(hook) };
    STATE.with(|state| state.borrow_mut().take());
}

impl Drop for Hook {
    fn drop(&mut self) {
        // SAFETY: plain message post to the hook thread, whose queue exists.
        let _ = unsafe { PostThreadMessageW(self.thread_id, WM_QUIT, WPARAM(0), LPARAM(0)) };
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use windows::Win32::UI::WindowsAndMessaging::KBDLLHOOKSTRUCT_FLAGS;

    use super::*;

    fn event(scan: u32, vk: u32, flags: u32) -> KBDLLHOOKSTRUCT {
        KBDLLHOOKSTRUCT {
            vkCode: vk,
            scanCode: scan,
            flags: KBDLLHOOKSTRUCT_FLAGS(flags),
            time: 0,
            dwExtraInfo: 0,
        }
    }

    /// What the forward callback saw.
    type Seen = Arc<Mutex<Vec<(KeyCode, bool)>>>;

    fn state(active: bool) -> (State, Arc<AtomicBool>, Seen) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        let active = Arc::new(AtomicBool::new(active));
        let state = State {
            active: Arc::clone(&active),
            forward: Box::new(move |key, down| sink.lock().unwrap().push((key, down))),
            taken: HashSet::new(),
        };
        (state, active, seen)
    }

    const UP: u32 = 0x80;
    const EXT: u32 = 0x01;
    const INJECTED: u32 = 0x10;

    #[test]
    fn translates_scan_codes_with_vk_fallback() {
        assert_eq!(translate(&event(0x1E, 0x41, 0)), Some(KeyCode::KeyA));
        assert_eq!(translate(&event(0x4B, 0x25, EXT)), Some(KeyCode::ArrowLeft));
        assert_eq!(translate(&event(0x4B, 0x64, 0)), Some(KeyCode::Numpad4));
        assert_eq!(translate(&event(0x45, 0x90, EXT)), Some(KeyCode::NumLock));
        assert_eq!(translate(&event(0x45, 0x13, 0)), Some(KeyCode::Pause));
        assert_eq!(
            translate(&event(0x56, 0xE2, 0)),
            Some(KeyCode::IntlBackslash)
        );
        assert_eq!(translate(&event(0x73, 0xC1, 0)), Some(KeyCode::IntlRo));
        // A media key reported without a scan code.
        assert_eq!(translate(&event(0, 0xB3, 0)), Some(KeyCode::MediaPlayPause));
        // The left Ctrl Windows sends with AltGr.
        assert_eq!(translate(&event(0x21D, 0xA2, 0)), None);
    }

    #[test]
    fn takes_keys_only_while_active_and_keeps_pairs_whole() {
        let (mut state, active, seen) = state(false);
        // Pressed before the Viewer was active: both halves stay local.
        assert!(!state.on_event(&event(0x38, 0xA4, 0)));
        active.store(true, Ordering::Relaxed);
        assert!(!state.on_event(&event(0x38, 0xA4, UP)));
        // Alt+Tab while active goes to the remote.
        assert!(state.on_event(&event(0x38, 0xA4, 0)));
        assert!(state.on_event(&event(0x0F, 0x09, 0)));
        // Deactivated mid-press: releases still follow their presses.
        active.store(false, Ordering::Relaxed);
        assert!(state.on_event(&event(0x0F, 0x09, UP)));
        assert!(state.on_event(&event(0x38, 0xA4, UP)));
        assert_eq!(
            *seen.lock().unwrap(),
            [
                (KeyCode::AltLeft, true),
                (KeyCode::Tab, true),
                (KeyCode::Tab, false),
                (KeyCode::AltLeft, false),
            ]
        );
    }

    #[test]
    fn altgr_fake_ctrl_is_taken_but_not_forwarded() {
        let (mut state, _, seen) = state(true);
        assert!(state.on_event(&event(0x21D, 0xA2, 0)));
        assert!(state.on_event(&event(0x38, 0xA5, EXT)));
        assert!(state.on_event(&event(0x21D, 0xA2, UP)));
        assert!(state.on_event(&event(0x38, 0xA5, EXT | UP)));
        assert_eq!(
            *seen.lock().unwrap(),
            [(KeyCode::AltRight, true), (KeyCode::AltRight, false)]
        );
    }

    /// Inactive, so every key still reaches the local system.
    #[test]
    #[ignore = "installs a hook on the live desktop"]
    fn installs_and_removes_cleanly() {
        let hook = install(Arc::new(AtomicBool::new(false)), Box::new(|_, _| {})).unwrap();
        drop(hook);
        let again = install(Arc::new(AtomicBool::new(false)), Box::new(|_, _| {})).unwrap();
        drop(again);
    }

    #[test]
    fn injected_and_unknown_keys_stay_local() {
        let (mut state, _, seen) = state(true);
        assert!(!state.on_event(&event(0x1E, 0x41, INJECTED)));
        assert!(!state.on_event(&event(0x7F, 0xFF, 0)));
        assert!(!state.on_event(&event(0x7F, 0xFF, UP)));
        assert!(seen.lock().unwrap().is_empty());
    }
}
