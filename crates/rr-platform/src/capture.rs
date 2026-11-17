//! Screen capture (blueprint v2 §3, §8.3).
//!
//! One monitor at a time, delivered as BGRA in system memory (the M2 CPU
//! path). Capturers only produce an image when the screen changed, so a
//! static screen costs no work downstream (§8.2).
//!
//! Backends: DXGI Desktop Duplication on Windows; on Linux, X11 (MIT-SHM
//! woken by XDamage) or, in Wayland sessions, the xdg-desktop-portal
//! ScreenCast interface with PipeWire. `RUSTREMOTE_CAPTURE=x11|portal`
//! overrides the Linux choice.

use std::time::{Duration, Instant};

use crate::input::{Area, InputBackend, InputError, SharedArea};

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
    /// The local user declined the system's screen-sharing dialog, let it
    /// time out, or stopped sharing (Wayland portal).
    #[error("the local user declined or stopped screen sharing")]
    Denied,
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
    #[cfg(target_os = "linux")]
    {
        use crate::linux::{Backend, backend, portal, x11};
        match backend()? {
            Backend::X11 => x11::monitors(),
            Backend::Portal => Ok(portal::monitors()),
        }
    }
}

/// Opens a capturer for monitor `id` (see [`monitors`]), view only.
///
/// # Errors
/// [`CaptureError::NoSuchMonitor`], [`CaptureError::Unsupported`] or an
/// OS failure.
pub fn open(id: u8) -> Result<Box<dyn ScreenCapturer>, CaptureError> {
    open_screen(id, false).map(|screen| screen.capturer)
}

/// A monitor opened for a session: its capturer and, with remote control,
/// the matching input backend.
pub struct Screen {
    /// The capturer. Not `Send`: keep it on the thread that opened it.
    pub capturer: Box<dyn ScreenCapturer>,
    /// `None` when control was not asked for; otherwise the backend (to
    /// wrap in an [`Injector`](crate::input::Injector), on any thread) or
    /// why there is none, in which case the session can stay view only.
    pub input: Option<Result<Box<dyn InputBackend>, InputError>>,
    /// Where the captured monitor is, as input needs it. Keep it current
    /// with [`Area::of`]`(capturer.monitor())` after each capture, since
    /// the monitor may move or change resolution.
    pub area: SharedArea,
}

impl std::fmt::Debug for Screen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Screen")
            .field("monitor", self.capturer.monitor())
            .field(
                "input",
                &self
                    .input
                    .as_ref()
                    .map(|input| input.as_ref().map(|backend| backend.name())),
            )
            .field("area", &self.area.get())
            .finish()
    }
}

/// Opens monitor `id` (see [`monitors`]) and, with `control`, an input
/// backend for it. On Wayland both come from one portal session, so the
/// system dialog asks for the screen and for keyboard and pointer at once.
///
/// # Errors
/// Capture failures only: [`CaptureError::NoSuchMonitor`],
/// [`CaptureError::Unsupported`], [`CaptureError::Denied`] or an OS
/// failure. Input failures are in [`Screen::input`].
pub fn open_screen(id: u8, control: bool) -> Result<Screen, CaptureError> {
    let area = SharedArea::default();
    let (capturer, input) = open_backends(id, control, &area)?;
    area.set(Area::of(capturer.monitor()));
    Ok(Screen {
        capturer,
        input,
        area,
    })
}

type Backends = (
    Box<dyn ScreenCapturer>,
    Option<Result<Box<dyn InputBackend>, InputError>>,
);

fn open_backends(id: u8, control: bool, area: &SharedArea) -> Result<Backends, CaptureError> {
    #[cfg(windows)]
    {
        use crate::win::{capture::DxgiCapturer, input::SendInputBackend};
        let capturer = DxgiCapturer::open(id)?;
        let input = control
            .then(|| Ok(Box::new(SendInputBackend::new(area.clone())) as Box<dyn InputBackend>));
        Ok((Box::new(capturer), input))
    }
    #[cfg(target_os = "linux")]
    {
        use crate::linux::{Backend, backend, portal, x11, x11_input};
        match backend()? {
            Backend::X11 => {
                let capturer = x11::X11Capturer::open(id)?;
                let input = control.then(|| {
                    x11_input::XTestBackend::open(area.clone())
                        .map(|backend| Box::new(backend) as Box<dyn InputBackend>)
                });
                Ok((Box::new(capturer), input))
            }
            Backend::Portal => {
                let (capturer, input) = portal::PortalCapturer::open(id, control)?;
                let input = input
                    .map(|input| input.map(|backend| Box::new(backend) as Box<dyn InputBackend>));
                Ok((Box::new(capturer), input))
            }
        }
    }
}

/// Whether [`open`] asks the local user to pick the screen in a system
/// dialog (Wayland portal). [`monitors`] then lists a single placeholder
/// of unknown size (0 × 0), and the real size comes with the frames.
#[must_use]
pub fn picks_in_dialog() -> bool {
    #[cfg(target_os = "linux")]
    {
        matches!(crate::linux::backend(), Ok(crate::linux::Backend::Portal))
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
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
