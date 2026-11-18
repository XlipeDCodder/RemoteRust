//! The session border on Windows (see [`crate::border`]): four layered,
//! click-through, topmost tool windows on a thread with its own message
//! loop, painted by the system with the class brush.
#![allow(unsafe_code)] // FFI module: every block below is justified with `SAFETY:`.

use std::sync::mpsc;
use std::thread::JoinHandle;

use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::{CreateSolidBrush, DeleteObject, HBRUSH, HGDIOBJ};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, HTTRANSPARENT,
    HWND_TOPMOST, LWA_ALPHA, MSG, PM_NOREMOVE, PeekMessageW, PostThreadMessageW, RegisterClassExW,
    SW_SHOWNOACTIVATE, SWP_NOACTIVATE, SWP_SHOWWINDOW, SetLayeredWindowAttributes,
    SetWindowDisplayAffinity, SetWindowPos, ShowWindow, UnregisterClassW, WDA_EXCLUDEFROMCAPTURE,
    WM_APP, WM_NCHITTEST, WM_QUIT, WM_USER, WNDCLASSEXW, WS_EX_LAYERED, WS_EX_NOACTIVATE,
    WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_EX_TRANSPARENT, WS_POPUP,
};
use windows::core::w;

use crate::border::{BorderError, COLOR, Rect, strips};
use crate::input::Area;

/// Posted to the border thread: new areas are waiting in the channel.
const WM_MOVE_BORDER: u32 = WM_APP + 1;

fn os_error(context: &'static str, err: &windows::core::Error) -> BorderError {
    BorderError::Os {
        context,
        message: err.message(),
    }
}

/// The border thread; stopped (and the windows destroyed) on drop.
pub(crate) struct Border {
    thread_id: u32,
    moves: mpsc::Sender<Area>,
    thread: Option<JoinHandle<()>>,
}

impl Border {
    pub(crate) fn show(area: Area) -> Result<Self, BorderError> {
        let (ready, started) = mpsc::channel::<Result<u32, BorderError>>();
        let (moves, moved) = mpsc::channel::<Area>();
        let thread = std::thread::Builder::new()
            .name("rr-border".to_owned())
            .spawn(move || run(area, &moved, &ready))
            .map_err(|err| BorderError::Os {
                context: "starting the border thread",
                message: err.to_string(),
            })?;
        match started.recv() {
            Ok(Ok(thread_id)) => Ok(Self {
                thread_id,
                moves,
                thread: Some(thread),
            }),
            Ok(Err(err)) => {
                let _ = thread.join();
                Err(err)
            }
            Err(_) => {
                let _ = thread.join();
                Err(BorderError::Os {
                    context: "starting the border thread",
                    message: "the thread ended early".to_owned(),
                })
            }
        }
    }

    pub(crate) fn move_to(&self, area: Area) {
        if self.moves.send(area).is_ok() {
            // SAFETY: plain message post to the border thread, whose queue
            // exists (created before `show` returned).
            let _ =
                unsafe { PostThreadMessageW(self.thread_id, WM_MOVE_BORDER, WPARAM(0), LPARAM(0)) };
        }
    }
}

impl Drop for Border {
    fn drop(&mut self) {
        // SAFETY: plain message post to the border thread.
        let _ = unsafe { PostThreadMessageW(self.thread_id, WM_QUIT, WPARAM(0), LPARAM(0)) };
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_NCHITTEST {
        // Clicks go to whatever lies below.
        return LRESULT(HTTRANSPARENT as isize);
    }
    // SAFETY: default handling (painting the class brush included) of a
    // message for one of this thread's windows.
    unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
}

/// The class brush; deleted on drop.
struct Brush(HBRUSH);

impl Drop for Brush {
    fn drop(&mut self) {
        // SAFETY: the brush created below, no longer used by any window
        // (they are destroyed first).
        let _ = unsafe { DeleteObject(HGDIOBJ(self.0.0)) };
    }
}

/// `0xRRGGBB` as a GDI `COLORREF` (`0x00BBGGRR`).
const fn colorref(rgb: u32) -> COLORREF {
    COLORREF(((rgb & 0xFF) << 16) | (rgb & 0xFF00) | ((rgb >> 16) & 0xFF))
}

fn run(area: Area, moved: &mpsc::Receiver<Area>, ready: &mpsc::Sender<Result<u32, BorderError>>) {
    let mut msg = MSG::default();
    // Creates this thread's message queue before anyone can post to it.
    // SAFETY: `msg` is a valid out-parameter.
    let _ = unsafe { PeekMessageW(&raw mut msg, None, WM_USER, WM_USER, PM_NOREMOVE) };
    // SAFETY: the module handle of this executable; no preconditions.
    let module = match unsafe { GetModuleHandleW(None) } {
        Ok(module) => module,
        Err(err) => {
            let _ = ready.send(Err(os_error("GetModuleHandleW", &err)));
            return;
        }
    };
    // SAFETY: plain GDI object creation; owned by `Brush`.
    let brush = Brush(unsafe { CreateSolidBrush(colorref(COLOR)) });
    let class = WNDCLASSEXW {
        cbSize: u32::try_from(size_of::<WNDCLASSEXW>()).unwrap_or(0),
        lpfnWndProc: Some(window_proc),
        hInstance: module.into(),
        hbrBackground: brush.0,
        lpszClassName: w!("RustRemoteSessionBorder"),
        ..Default::default()
    };
    // SAFETY: `class` is fully initialized; its strings are static. A class
    // left registered by an earlier border is reused (the call then fails
    // harmlessly and CreateWindowExW finds the old one).
    let _ = unsafe { RegisterClassExW(&raw const class) };
    let mut windows = Vec::with_capacity(4);
    for rect in strips(area) {
        match create(module.into(), rect) {
            Ok(hwnd) => windows.push(hwnd),
            Err(err) => {
                destroy(&windows);
                let _ = ready.send(Err(err));
                return;
            }
        }
    }
    // SAFETY: no preconditions.
    let _ = ready.send(Ok(unsafe { GetCurrentThreadId() }));

    // WM_QUIT (0) or an error (-1) ends the loop.
    // SAFETY: `msg` is a valid out-parameter.
    while unsafe { GetMessageW(&raw mut msg, None, 0, 0) }.0 > 0 {
        if msg.hwnd.is_invalid() && msg.message == WM_MOVE_BORDER {
            if let Some(area) = moved.try_iter().last() {
                for (hwnd, rect) in windows.iter().zip(strips(area)) {
                    place(*hwnd, rect);
                }
            }
            continue;
        }
        // SAFETY: a message just retrieved for this thread.
        unsafe { DispatchMessageW(&raw const msg) };
    }
    destroy(&windows);
    // SAFETY: the class registered above; its windows are gone.
    let _ = unsafe { UnregisterClassW(w!("RustRemoteSessionBorder"), Some(module.into())) };
    drop(brush);
}

fn create(
    instance: windows::Win32::Foundation::HINSTANCE,
    (left, top, width, height): Rect,
) -> Result<HWND, BorderError> {
    let size = |value: u32| i32::try_from(value).unwrap_or(i32::MAX);
    // SAFETY: creates a top-level window of the class registered on this
    // thread; it is destroyed on this thread before the thread ends.
    let hwnd = unsafe {
        CreateWindowExW(
            WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
            w!("RustRemoteSessionBorder"),
            w!("RustRemote: screen shared"),
            WS_POPUP,
            left,
            top,
            size(width),
            size(height),
            None,
            None,
            Some(instance),
            None,
        )
    }
    .map_err(|err| os_error("CreateWindowExW", &err))?;
    // A layered window shows nothing until it has attributes: fully opaque.
    // SAFETY: a window created above, on this thread.
    if let Err(err) = unsafe { SetLayeredWindowAttributes(hwnd, COLORREF(0), 255, LWA_ALPHA) } {
        destroy(&[hwnd]);
        return Err(os_error("SetLayeredWindowAttributes", &err));
    }
    // Keep the frame out of the shared picture; older Windows versions
    // refuse, and the Viewer then sees it too.
    // SAFETY: a window created above, on this thread.
    let _ = unsafe { SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) };
    // SAFETY: a window created above, on this thread.
    let _ = unsafe { ShowWindow(hwnd, SW_SHOWNOACTIVATE) };
    Ok(hwnd)
}

fn place(hwnd: HWND, (left, top, width, height): Rect) {
    let size = |value: u32| i32::try_from(value).unwrap_or(i32::MAX);
    // SAFETY: a window this thread created and still owns.
    let _ = unsafe {
        SetWindowPos(
            hwnd,
            Some(HWND_TOPMOST),
            left,
            top,
            size(width),
            size(height),
            SWP_NOACTIVATE | SWP_SHOWWINDOW,
        )
    };
}

fn destroy(windows: &[HWND]) {
    for hwnd in windows {
        // SAFETY: a window this thread created, destroyed once.
        let _ = unsafe { DestroyWindow(*hwnd) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colors_are_converted_to_gdi_order() {
        assert_eq!(colorref(0x00E5_3935), COLORREF(0x0035_39E5));
    }

    /// Shows the border for a moment on the primary monitor.
    #[test]
    #[ignore = "draws on the desktop"]
    fn shows_and_removes_the_border() {
        let mut border = crate::border::Border::show(Area {
            left: 0,
            top: 0,
            width: 800,
            height: 600,
        })
        .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(800));
        border.follow(Area {
            left: 100,
            top: 100,
            width: 800,
            height: 600,
        });
        std::thread::sleep(std::time::Duration::from_millis(800));
        drop(border);
    }
}
