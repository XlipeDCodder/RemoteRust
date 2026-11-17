//! Screen capture (blueprint v2 §3, §8.3).
//!
//! One monitor at a time, delivered as BGRA in system memory (the M2 CPU
//! path). Capturers only produce an image when the screen changed, so a
//! static screen costs no work downstream (§8.2).
//!
//! Backends: DXGI Desktop Duplication on Windows. X11 (MIT-SHM) and
//! Wayland (portal + PipeWire) follow later in M2.

use std::time::{Duration, Instant};

/// Maximum number of monitors reported.
pub const MAX_MONITORS: usize = 16;

/// A monitor that can be captured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Monitor {
    /// Stable for the life of the process: enumeration order.
    pub id: u8,
    /// OS name, e.g. `DISPLAY1`.
    pub name: String,
    /// Width in physical pixels.
    pub width: u32,
    /// Height in physical pixels.
    pub height: u32,
    /// Left edge on the virtual desktop.
    pub left: i32,
    /// Top edge on the virtual desktop.
    pub top: i32,
    /// Whether this is the primary monitor.
    pub primary: bool,
}

/// One captured image, valid only during the capture callback.
#[derive(Debug, Clone, Copy)]
pub struct Frame<'a> {
    /// Width in pixels.
    pub width: u32,
    /// Height in pixels.
    pub height: u32,
    /// Bytes from one row to the next (at least `width * 4`).
    pub stride: usize,
    /// Pixels in B, G, R, A byte order; `stride * height` bytes.
    pub bgra: &'a [u8],
    /// Screen updates folded into this image since the previous one
    /// (at least 1).
    pub accumulated: u32,
    /// When the OS handed over the new image: the time from here to the
    /// callback is the capture (copy) cost, excluding the wait for a change.
    pub acquired: Instant,
}

/// Capture failures.
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    /// No backend for this platform or session type (yet).
    #[error("screen capture is not supported here: {0}")]
    Unsupported(&'static str),
    /// The requested monitor does not exist.
    #[error("monitor {0} not found")]
    NoSuchMonitor(u8),
    /// Capture was interrupted by a desktop switch, a display mode change
    /// or the secure desktop (UAC, lock screen). Calling `capture` again
    /// tries to recover.
    #[error("capture was interrupted (desktop switch, display change or secure desktop)")]
    AccessLost,
    /// An OS call failed.
    #[error("{context} failed: {message} ({code:#010x})")]
    Os {
        /// The failing call.
        context: &'static str,
        /// OS error code (an `HRESULT` on Windows).
        code: u32,
        /// OS error text.
        message: String,
    },
}

/// A screen capturer bound to one monitor. Not `Send`: graphics contexts
/// are thread-affine, so create it on the thread that uses it.
pub trait ScreenCapturer {
    /// The monitor being captured.
    fn monitor(&self) -> &Monitor;

    /// Waits up to `timeout` for the screen to change. If it did, calls
    /// `on_frame` with the new image and returns `true`; otherwise returns
    /// `false` without calling it.
    ///
    /// # Errors
    /// [`CaptureError::AccessLost`] (recoverable: call again later) or any
    /// other capture failure.
    fn capture(
        &mut self,
        timeout: Duration,
        on_frame: &mut dyn FnMut(Frame<'_>),
    ) -> Result<bool, CaptureError>;
}

/// Lists the monitors attached to the desktop.
///
/// # Errors
/// [`CaptureError::Unsupported`] or an OS failure.
pub fn monitors() -> Result<Vec<Monitor>, CaptureError> {
    #[cfg(windows)]
    {
        crate::win::capture::monitors()
    }
    #[cfg(not(windows))]
    {
        Err(CaptureError::Unsupported(
            "Linux capture arrives later in M2",
        ))
    }
}

/// Opens a capturer for monitor `id` (see [`monitors`]).
///
/// # Errors
/// [`CaptureError::NoSuchMonitor`], [`CaptureError::Unsupported`] or an
/// OS failure.
pub fn open(id: u8) -> Result<Box<dyn ScreenCapturer>, CaptureError> {
    #[cfg(windows)]
    {
        Ok(Box::new(crate::win::capture::DxgiCapturer::open(id)?))
    }
    #[cfg(not(windows))]
    {
        let _ = id;
        Err(CaptureError::Unsupported(
            "Linux capture arrives later in M2",
        ))
    }
}

/// Makes this process see physical pixels on every monitor (per-monitor
/// DPI awareness v2), as capture and input coordinates require. Call once
/// at startup, before any window exists. Does nothing on Linux.
///
/// # Errors
/// An OS failure, e.g. when the awareness was already set (by a manifest
/// or an earlier call); callers may ignore it.
pub fn set_dpi_aware() -> Result<(), CaptureError> {
    #[cfg(windows)]
    {
        crate::win::dpi::set_per_monitor_v2()
    }
    #[cfg(not(windows))]
    {
        Ok(())
    }
}
