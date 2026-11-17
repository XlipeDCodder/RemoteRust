//! X11 screen capture (blueprint v2 §3, §8.3), M2 CPU path: one RandR
//! monitor of the root window, copied through MIT-SHM and woken by
//! XDamage, so a static screen costs a blocking wait and nothing else.
//!
//! The image is the root window as shown on screen. The mouse pointer is
//! not part of it; it travels separately (M3). Under XWayland the root
//! window only holds X clients, which is why Wayland sessions use the
//! portal backend instead.
#![allow(unsafe_code)] // mmap of the shared image; every block below is justified with `SAFETY:`.

use std::ffi::c_void;
use std::fmt::Display;
use std::os::fd::AsFd as _;
use std::ptr::NonNull;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags};
use rustix::fs::MemfdFlags;
use rustix::mm::{MapFlags, ProtFlags};
use x11rb::NONE;
use x11rb::connection::{Connection as _, RequestConnection as _};
use x11rb::errors::ReplyError;
use x11rb::protocol::Event;
use x11rb::protocol::damage::{self, ConnectionExt as _, ReportLevel};
use x11rb::protocol::randr::{self, ConnectionExt as _, NotifyMask};
use x11rb::protocol::shm::{self, ConnectionExt as _};
use x11rb::protocol::xfixes::{self, ConnectionExt as _};
use x11rb::protocol::xproto::{self, ConnectionExt as _, ImageFormat, ImageOrder, Rectangle};
use x11rb::rust_connection::RustConnection;

use crate::capture::{CaptureError, Frame, MAX_MONITORS, Monitor, ScreenCapturer};

/// Wraps an X11 failure for `context`.
fn x11_error(context: &'static str, err: impl Display) -> CaptureError {
    CaptureError::Os {
        context,
        code: 0,
        message: err.to_string(),
    }
}

/// Opens the display named by `$DISPLAY` and returns its default screen.
fn connect() -> Result<(RustConnection, xproto::Screen), CaptureError> {
    let (conn, screen) =
        x11rb::connect(None).map_err(|err| x11_error("connecting to the X server", err))?;
    let screen = conn
        .setup()
        .roots
        .get(screen)
        .cloned()
        .ok_or_else(|| x11_error("connecting to the X server", "no such screen"))?;
    Ok((conn, screen))
}

/// Whether the server has extension `name`.
fn has_extension(conn: &RustConnection, name: &'static str) -> Result<bool, CaptureError> {
    conn.extension_information(name)
        .map(|info| info.is_some())
        .map_err(|err| x11_error("QueryExtension", err))
}

/// Whether RandR 1.5 (monitor objects) is available.
fn randr_monitors(conn: &RustConnection) -> Result<bool, CaptureError> {
    if !has_extension(conn, randr::X11_EXTENSION_NAME)? {
        return Ok(false);
    }
    let version = conn
        .randr_query_version(1, 5)
        .map_err(|err| x11_error("RRQueryVersion", err))?
        .reply()
        .map_err(|err| x11_error("RRQueryVersion", err))?;
    Ok((version.major_version, version.minor_version) >= (1, 5))
}

/// Lists the active RandR monitors in server order, or the whole screen
/// as one monitor when RandR 1.5 is missing. Exactly one is primary.
fn list(conn: &RustConnection, screen: &xproto::Screen) -> Result<Vec<Monitor>, CaptureError> {
    let mut monitors = Vec::new();
    if randr_monitors(conn)? {
        let reply = conn
            .randr_get_monitors(screen.root, true)
            .map_err(|err| x11_error("RRGetMonitors", err))?
            .reply()
            .map_err(|err| x11_error("RRGetMonitors", err))?;
        for (info, id) in reply.monitors.iter().take(MAX_MONITORS).zip(0u8..) {
            let name = conn
                .get_atom_name(info.name)
                .ok()
                .and_then(|cookie| cookie.reply().ok())
                .map_or_else(
                    || format!("monitor {id}"),
                    |reply| String::from_utf8_lossy(&reply.name).into_owned(),
                );
            monitors.push(Monitor {
                id,
                name,
                width: info.width.into(),
                height: info.height.into(),
                left: info.x.into(),
                top: info.y.into(),
                primary: info.primary,
            });
        }
    }
    if monitors.is_empty() {
        monitors.push(Monitor {
            id: 0,
            name: "screen".to_owned(),
            width: screen.width_in_pixels.into(),
            height: screen.height_in_pixels.into(),
            left: 0,
            top: 0,
            primary: true,
        });
    }
    if !monitors.iter().any(|monitor| monitor.primary)
        && let Some(first) = monitors.first_mut()
    {
        first.primary = true;
    }
    Ok(monitors)
}

/// Lists the monitors of the X display.
pub(crate) fn monitors() -> Result<Vec<Monitor>, CaptureError> {
    let (conn, screen) = connect()?;
    list(&conn, &screen)
}

/// Pixels must arrive as 32-bit little-endian BGRX (a ZPixmap of a 24- or
/// 32-bit true-color visual), the layout everything downstream expects.
fn check_format(conn: &RustConnection, screen: &xproto::Screen) -> Result<(), CaptureError> {
    let setup = conn.setup();
    let bits_per_pixel = setup
        .pixmap_formats
        .iter()
        .find(|format| format.depth == screen.root_depth)
        .map(|format| format.bits_per_pixel);
    let visual = screen
        .allowed_depths
        .iter()
        .flat_map(|depth| &depth.visuals)
        .find(|visual| visual.visual_id == screen.root_visual);
    let bgrx = visual.is_some_and(|visual| {
        (visual.red_mask, visual.green_mask, visual.blue_mask) == (0x00ff_0000, 0x0000_ff00, 0xff)
    });
    if matches!(screen.root_depth, 24 | 32)
        && bits_per_pixel == Some(32)
        && setup.image_byte_order == ImageOrder::LSB_FIRST
        && bgrx
    {
        Ok(())
    } else {
        Err(CaptureError::Unsupported(
            "X11 capture needs a 24- or 32-bit little-endian BGRX screen",
        ))
    }
}

/// Bytes of one BGRX image of `monitor`.
fn image_len(monitor: &Monitor) -> Result<usize, CaptureError> {
    usize::try_from(monitor.width)
        .ok()
        .zip(usize::try_from(monitor.height).ok())
        .and_then(|(width, height)| width.checked_mul(height)?.checked_mul(4))
        .ok_or(CaptureError::Unsupported("monitor too large"))
}

/// Whether `rect` (root coordinates) overlaps `monitor`.
fn overlaps(rect: &Rectangle, monitor: &Monitor) -> bool {
    let (left, top) = (i64::from(rect.x), i64::from(rect.y));
    let (right, bottom) = (left + i64::from(rect.width), top + i64::from(rect.height));
    let (m_left, m_top) = (i64::from(monitor.left), i64::from(monitor.top));
    let m_right = m_left + i64::from(monitor.width);
    let m_bottom = m_top + i64::from(monitor.height);
    left < m_right && m_left < right && top < m_bottom && m_top < bottom
}

/// A shared-memory segment the X server writes images into (MIT-SHM 1.2:
/// a memfd passed over the socket, so no SysV segment lingers if the
/// process dies).
struct SharedImage {
    seg: shm::Seg,
    ptr: NonNull<c_void>,
    len: usize,
}

impl SharedImage {
    /// Creates and attaches a segment of `len` bytes. `None` when the
    /// server cannot share memory with this process (no MIT-SHM 1.2, or a
    /// remote display): capture then falls back to plain `GetImage`.
    fn new(conn: &RustConnection, len: usize) -> Result<Option<Self>, CaptureError> {
        if !has_extension(conn, shm::X11_EXTENSION_NAME)? {
            return Ok(None);
        }
        let version = conn
            .shm_query_version()
            .map_err(|err| x11_error("ShmQueryVersion", err))?
            .reply()
            .map_err(|err| x11_error("ShmQueryVersion", err))?;
        if (version.major_version, version.minor_version) < (1, 2) {
            return Ok(None);
        }
        let fd = rustix::fs::memfd_create("rustremote-capture", MemfdFlags::CLOEXEC)
            .map_err(|err| x11_error("memfd_create", err))?;
        let size =
            u64::try_from(len).map_err(|_| CaptureError::Unsupported("monitor too large"))?;
        rustix::fs::ftruncate(&fd, size).map_err(|err| x11_error("ftruncate", err))?;
        // SAFETY: maps a fresh memfd of exactly `len` bytes, read-only and
        // shared, at an address of the kernel's choosing. The mapping is
        // owned by the value built below and unmapped in its `Drop`.
        let ptr = unsafe {
            rustix::mm::mmap(
                std::ptr::null_mut(),
                len,
                ProtFlags::READ,
                MapFlags::SHARED,
                &fd,
                0,
            )
        }
        .map_err(|err| x11_error("mmap", err))?;
        let ptr = NonNull::new(ptr).ok_or_else(|| x11_error("mmap", "null mapping"))?;
        let seg = conn
            .generate_id()
            .map_err(|err| x11_error("ShmAttachFd", err))?;
        let image = Self { seg, ptr, len };
        // The server writes into the segment, so it is attached read-write.
        // Any failure (e.g. fd passing over TCP) means "no shared memory".
        let attached = conn
            .shm_attach_fd(seg, fd, false)
            .ok()
            .and_then(|cookie| cookie.check().ok());
        Ok(attached.map(|()| image))
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: `ptr` maps `len` readable bytes for the life of `self`.
        // The server writes only while it handles ShmGetImage, and callers
        // read only after that request's reply arrived.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr().cast::<u8>(), self.len) }
    }
}

impl Drop for SharedImage {
    fn drop(&mut self) {
        // SAFETY: unmaps the mapping made in `new`, once; no slice from
        // `bytes` outlives `self`.
        let _ = unsafe { rustix::mm::munmap(self.ptr.as_ptr(), self.len) };
    }
}

/// Captures one monitor of an X display.
pub(crate) struct X11Capturer {
    conn: RustConnection,
    screen: xproto::Screen,
    monitor: Monitor,
    image: Option<SharedImage>,
    damage: damage::Damage,
    damaged: xfixes::Region,
    /// Grab on the next call without waiting for damage: the first image,
    /// and the first one after a screen change.
    pending: bool,
    /// The screen layout changed: re-read the monitor before grabbing.
    reset: bool,
}

impl X11Capturer {
    /// Opens monitor `id` (as listed by [`monitors`]).
    pub(crate) fn open(id: u8) -> Result<Self, CaptureError> {
        let (conn, screen) = connect()?;
        let monitor = list(&conn, &screen)?
            .into_iter()
            .find(|monitor| monitor.id == id)
            .ok_or(CaptureError::NoSuchMonitor(id))?;
        check_format(&conn, &screen)?;
        if !has_extension(&conn, damage::X11_EXTENSION_NAME)?
            || !has_extension(&conn, xfixes::X11_EXTENSION_NAME)?
        {
            return Err(CaptureError::Unsupported(
                "the X server lacks the DAMAGE or XFIXES extension",
            ));
        }
        // Extensions must learn the client's version before first use.
        conn.xfixes_query_version(5, 0)
            .map_err(|err| x11_error("XFixesQueryVersion", err))?
            .reply()
            .map_err(|err| x11_error("XFixesQueryVersion", err))?;
        conn.damage_query_version(1, 1)
            .map_err(|err| x11_error("DamageQueryVersion", err))?
            .reply()
            .map_err(|err| x11_error("DamageQueryVersion", err))?;

        // One notification each time the damage goes from empty to
        // non-empty; taking the damage re-arms it.
        let damage = conn
            .generate_id()
            .map_err(|err| x11_error("DamageCreate", err))?;
        conn.damage_create(damage, screen.root, ReportLevel::NON_EMPTY)
            .map_err(|err| x11_error("DamageCreate", err))?;
        let damaged = conn
            .generate_id()
            .map_err(|err| x11_error("CreateRegion", err))?;
        conn.xfixes_create_region(damaged, &[])
            .map_err(|err| x11_error("CreateRegion", err))?;
        if randr_monitors(&conn)? {
            conn.randr_select_input(screen.root, NotifyMask::SCREEN_CHANGE)
                .map_err(|err| x11_error("RRSelectInput", err))?;
        }
        let image = SharedImage::new(&conn, image_len(&monitor)?)?;
        conn.flush().map_err(|err| x11_error("flush", err))?;
        Ok(Self {
            conn,
            screen,
            monitor,
            image,
            damage,
            damaged,
            pending: true,
            reset: false,
        })
    }

    /// Whether images travel through shared memory (else `GetImage`).
    #[cfg(test)]
    fn shared(&self) -> bool {
        self.image.is_some()
    }

    /// Handles queued events; returns whether any damage was reported.
    fn drain_events(&mut self) -> Result<bool, CaptureError> {
        let mut damaged = false;
        while let Some(event) = self
            .conn
            .poll_for_event()
            .map_err(|err| x11_error("reading X events", err))?
        {
            match event {
                Event::DamageNotify(_) => damaged = true,
                Event::RandrScreenChangeNotify(_) => self.reset = true,
                _ => {}
            }
        }
        Ok(damaged)
    }

    /// Moves the accumulated damage into `self.damaged` (re-arming the
    /// notification) and tells whether any of it lies on this monitor.
    fn take_damage(&mut self) -> Result<bool, CaptureError> {
        self.conn
            .damage_subtract(self.damage, NONE, self.damaged)
            .map_err(|err| x11_error("DamageSubtract", err))?;
        let region = self
            .conn
            .xfixes_fetch_region(self.damaged)
            .map_err(|err| x11_error("FetchRegion", err))?
            .reply()
            .map_err(|err| x11_error("FetchRegion", err))?;
        Ok(region
            .rectangles
            .iter()
            .any(|rect| overlaps(rect, &self.monitor)))
    }

    /// Waits until damage touches this monitor (`true`) or `deadline`
    /// passes (`false`).
    fn wait_for_damage(&mut self, deadline: Instant) -> Result<bool, CaptureError> {
        loop {
            // Events are drained *before* the damage is taken: a
            // notification for damage after `take_damage` stays queued for
            // the next round, so no update is lost.
            if self.drain_events()? && self.take_damage()? {
                return Ok(true);
            }
            if self.reset {
                return Err(CaptureError::AccessLost);
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(false);
            }
            self.wait_readable(deadline - now)?;
        }
    }

    /// Blocks until the X connection has data or `timeout` passes.
    fn wait_readable(&self, timeout: Duration) -> Result<(), CaptureError> {
        let Ok(timeout) = timeout.min(Duration::from_secs(60)).try_into() else {
            return Ok(());
        };
        let fd = self.conn.stream().as_fd();
        let mut fds = [PollFd::from_borrowed_fd(fd, PollFlags::IN)];
        match rustix::event::poll(&mut fds, Some(&timeout)) {
            Ok(_) | Err(rustix::io::Errno::INTR) => Ok(()),
            Err(err) => Err(x11_error("poll", err)),
        }
    }

    /// Re-reads this monitor after a screen change (same id, maybe a new
    /// size) and reallocates the shared image if needed.
    fn reconfigure(&mut self) -> Result<(), CaptureError> {
        let monitor = list(&self.conn, &self.screen)?
            .into_iter()
            .find(|monitor| monitor.id == self.monitor.id)
            .ok_or(CaptureError::NoSuchMonitor(self.monitor.id))?;
        if (monitor.width, monitor.height) != (self.monitor.width, self.monitor.height) {
            if let Some(old) = self.image.take() {
                let _ = self.conn.shm_detach(old.seg);
            }
            self.image = SharedImage::new(&self.conn, image_len(&monitor)?)?;
        }
        self.monitor = monitor;
        self.reset = false;
        self.pending = true;
        Ok(())
    }

    /// Copies the monitor's pixels and hands them to `on_frame`.
    fn grab(&mut self, on_frame: &mut dyn FnMut(Frame<'_>)) -> Result<(), CaptureError> {
        let monitor = &self.monitor;
        let too_large = || CaptureError::Unsupported("monitor outside the X11 coordinate range");
        let x = i16::try_from(monitor.left).map_err(|_| too_large())?;
        let y = i16::try_from(monitor.top).map_err(|_| too_large())?;
        let width = u16::try_from(monitor.width).map_err(|_| too_large())?;
        let height = u16::try_from(monitor.height).map_err(|_| too_large())?;
        let stride = usize::from(width) * 4;
        let len = image_len(monitor)?;

        // A request failing with an X error means the geometry no longer
        // fits the screen (mode change in flight): recover via `reset`.
        let lost = |err: ReplyError, context| match err {
            ReplyError::X11Error(_) => CaptureError::AccessLost,
            ReplyError::ConnectionError(err) => x11_error(context, err),
        };
        // The server copies while handling the request, so the capture
        // (copy) time starts here, as it does at DXGI's acquire.
        let acquired = Instant::now();
        let owned;
        let bgra = match &self.image {
            Some(image) => {
                let reply = self
                    .conn
                    .shm_get_image(
                        self.screen.root,
                        x,
                        y,
                        width,
                        height,
                        u32::MAX,
                        ImageFormat::Z_PIXMAP.into(),
                        image.seg,
                        0,
                    )
                    .map_err(|err| x11_error("ShmGetImage", err))?
                    .reply();
                if let Err(err) = reply {
                    self.reset = true;
                    return Err(lost(err, "ShmGetImage"));
                }
                image.bytes()
            }
            None => {
                let reply = self
                    .conn
                    .get_image(
                        ImageFormat::Z_PIXMAP,
                        self.screen.root,
                        x,
                        y,
                        width,
                        height,
                        u32::MAX,
                    )
                    .map_err(|err| x11_error("GetImage", err))?
                    .reply();
                match reply {
                    Ok(reply) => {
                        owned = reply.data;
                        &owned
                    }
                    Err(err) => {
                        self.reset = true;
                        return Err(lost(err, "GetImage"));
                    }
                }
            }
        };
        let bgra = bgra
            .get(..len)
            .ok_or_else(|| x11_error("GetImage", "short image"))?;
        on_frame(Frame {
            width: monitor.width,
            height: monitor.height,
            stride,
            bgra,
            // X11 does not count updates: whatever happened since the last
            // grab is one image.
            accumulated: 1,
            acquired,
        });
        Ok(())
    }
}

impl ScreenCapturer for X11Capturer {
    fn monitor(&self) -> &Monitor {
        &self.monitor
    }

    fn capture(
        &mut self,
        timeout: Duration,
        on_frame: &mut dyn FnMut(Frame<'_>),
    ) -> Result<bool, CaptureError> {
        if self.reset {
            self.reconfigure()?;
        }
        if self.pending {
            // Take (and ignore) the damage so far: the grab covers it.
            self.drain_events()?;
            self.conn
                .damage_subtract(self.damage, NONE, NONE)
                .map_err(|err| x11_error("DamageSubtract", err))?;
        } else if !self.wait_for_damage(Instant::now() + timeout)? {
            return Ok(false);
        }
        self.grab(on_frame)?;
        self.pending = false;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn monitor(left: i32, top: i32, width: u32, height: u32) -> Monitor {
        Monitor {
            id: 0,
            name: "test".to_owned(),
            width,
            height,
            left,
            top,
            primary: true,
        }
    }

    fn rect(x: i16, y: i16, width: u16, height: u16) -> Rectangle {
        Rectangle {
            x,
            y,
            width,
            height,
        }
    }

    #[test]
    fn damage_counts_only_on_the_monitor() {
        let right = monitor(1920, 0, 1280, 1024);
        assert!(overlaps(&rect(1920, 0, 1, 1), &right));
        assert!(overlaps(&rect(1900, 10, 40, 40), &right));
        assert!(!overlaps(&rect(0, 0, 1920, 1080), &right));
        assert!(!overlaps(&rect(3200, 0, 10, 10), &right));
        assert!(!overlaps(&rect(1920, 1024, 10, 10), &right));
        assert!(!overlaps(&rect(1920, 0, 0, 0), &right));
    }

    #[test]
    fn image_size_is_checked() {
        assert_eq!(
            image_len(&monitor(0, 0, 1920, 1080)).unwrap(),
            1920 * 1080 * 4
        );
        assert!(image_len(&monitor(0, 0, u32::MAX, u32::MAX)).is_err());
    }

    /// Needs an X server; CI runs it under Xvfb.
    #[test]
    #[ignore = "needs an X server (DISPLAY)"]
    fn opens_with_shared_memory() {
        let capturer = X11Capturer::open(0).unwrap();
        println!(
            "{:?}, shared memory: {}",
            capturer.monitor,
            capturer.shared()
        );
        assert!(capturer.shared(), "a local X server should share memory");
    }

    /// Captures until a frame arrives or `limit` passes; returns the BGRA
    /// bytes of pixel (`x`, `y`) and how long it took.
    fn pixel_after_change(
        capturer: &mut X11Capturer,
        (x, y): (usize, usize),
        limit: Duration,
    ) -> Option<([u8; 4], Duration)> {
        let started = Instant::now();
        let mut seen = None;
        while seen.is_none() && started.elapsed() < limit {
            capturer
                .capture(Duration::from_millis(50), &mut |frame| {
                    let at = y * frame.stride + x * 4;
                    let pixel = frame.bgra[at..at + 4].try_into().unwrap();
                    seen = Some((pixel, started.elapsed()));
                })
                .unwrap();
        }
        seen
    }

    /// A window painted in a known color must wake the capture through
    /// DAMAGE and come out in B, G, R order. Needs an X server; CI runs it
    /// under Xvfb.
    #[test]
    #[ignore = "needs an X server (DISPLAY)"]
    fn damage_wakes_the_capture_with_the_right_colors() {
        let mut capturer = X11Capturer::open(0).unwrap();
        // The first call grabs at once; then a static screen yields nothing.
        assert!(capturer.capture(Duration::ZERO, &mut |_| {}).unwrap());
        assert!(
            !capturer
                .capture(Duration::from_millis(200), &mut |_| {})
                .unwrap()
        );

        // Another client maps a 0x336699 (R, G, B) window at (100, 100).
        let (painter, screen) = connect().unwrap();
        let window = painter.generate_id().unwrap();
        painter
            .create_window(
                screen.root_depth,
                window,
                screen.root,
                100,
                100,
                200,
                150,
                0,
                xproto::WindowClass::INPUT_OUTPUT,
                screen.root_visual,
                &xproto::CreateWindowAux::new()
                    .background_pixel(0x0033_6699)
                    .override_redirect(1),
            )
            .unwrap();
        painter.map_window(window).unwrap();
        painter.flush().unwrap();

        let (pixel, after) = pixel_after_change(&mut capturer, (150, 150), Duration::from_secs(3))
            .expect("no frame after the window appeared");
        println!("window seen after {after:?}: {pixel:02x?}");
        assert_eq!(pixel[..3], [0x99, 0x66, 0x33], "expected B, G, R bytes");
        assert!(after < Duration::from_secs(1));
    }
}
