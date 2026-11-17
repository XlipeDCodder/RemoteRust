//! Wayland screen capture and input (blueprint v2 §3, §8.3, §8.7), M2 CPU
//! path: the xdg-desktop-portal ScreenCast interface lets the local user
//! pick a monitor in the compositor's own dialog, then images arrive over
//! PipeWire as BGRx in shared memory.
//!
//! Compositors send an image only when the screen changed, so a static
//! screen costs a blocking wait and nothing else. The pointer is drawn
//! into the image: Wayland offers no other way to follow it yet.
//!
//! With remote control, the session is a RemoteDesktop one carrying the
//! same ScreenCast sources, so one dialog asks for the screen and for
//! keyboard and pointer; [`PortalInput`] then injects through it. Capture
//! and input share the session ([`Link`]), which closes when both are gone.

use std::future::Future;
use std::os::fd::OwnedFd;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ashpd::desktop::remote_desktop::{
    Axis, DeviceType, KeyState, RemoteDesktop, SelectDevicesOptions,
};
use ashpd::desktop::screencast::{
    CursorMode, Screencast, SelectSourcesOptions, SourceType, Stream,
};
use ashpd::desktop::{PersistMode, ResponseError, Session};
use pipewire as pw;
use pw::spa;
use pw::spa::param::ParamType;
use pw::spa::param::format::{FormatProperties, MediaSubtype, MediaType};
use pw::spa::param::video::{VideoFormat, VideoInfoRaw};
use pw::spa::pod::Pod;
use pw::spa::pod::serialize::PodSerializer;
use pw::spa::utils::{Direction, Fraction, Rectangle, SpaTypes};
use pw::stream::{StreamFlags, StreamState};

use crate::capture::{CaptureError, Frame, Monitor, ScreenCapturer};
use crate::input::{InputBackend, InputError, KeyCode, MouseButton, Notches};
use crate::keymap;

/// The name the single portal "monitor" goes by: the real choice happens
/// in the compositor's dialog.
const PICKED: &str = "picked in the sharing dialog";
/// Longest wait for the local user to pick a screen.
const PICK_TIMEOUT: Duration = Duration::from_secs(60);
/// Longest wait for the portal to take one input event.
const CALL_TIMEOUT: Duration = Duration::from_secs(1);
/// Devices remote control needs.
const DEVICES: DeviceType = DeviceType::KEYBOARD.union(DeviceType::POINTER);
/// Frame rate asked of the compositor: the Agent's software-path cap.
const STREAM_FPS: u32 = 30;

/// The portal shows its own monitor list, so the Agent announces one
/// placeholder of unknown size (0 × 0).
pub(crate) fn monitors() -> Vec<Monitor> {
    vec![placeholder()]
}

fn placeholder() -> Monitor {
    Monitor {
        id: 0,
        name: PICKED.to_owned(),
        width: 0,
        height: 0,
        left: 0,
        top: 0,
        primary: true,
    }
}

/// Wraps a portal failure for `context`; a cancelled dialog is a denial.
fn portal_error(context: &'static str, err: ashpd::Error) -> CaptureError {
    match err {
        ashpd::Error::Response(ResponseError::Cancelled) => CaptureError::Denied,
        err => CaptureError::Os {
            context,
            code: 0,
            message: err.to_string(),
        },
    }
}

fn os_error(context: &'static str, message: impl ToString) -> CaptureError {
    CaptureError::Os {
        context,
        code: 0,
        message: message.to_string(),
    }
}

/// Why the stream stopped.
#[derive(Debug)]
enum End {
    /// The user stopped sharing (or the compositor ended the cast).
    Stopped,
    /// A PipeWire failure.
    Failed(String),
}

/// The newest image, handed from the PipeWire thread to the capturer.
#[derive(Default)]
struct Latest {
    pixels: Vec<u8>,
    width: u32,
    height: u32,
    stride: usize,
    /// How long copying the newest image out of PipeWire took.
    copy: Duration,
    /// Images published since the capturer last took one.
    fresh: u32,
    ended: Option<End>,
}

#[derive(Default)]
struct Shared {
    latest: Mutex<Latest>,
    ready: Condvar,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Latest> {
        self.latest.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Replaces the newest image ("latest frame wins").
    fn publish(&self, pixels: &[u8], width: u32, height: u32, stride: usize) {
        let started = Instant::now();
        let mut latest = self.lock();
        latest.pixels.clear();
        latest.pixels.extend_from_slice(pixels);
        latest.copy = started.elapsed();
        latest.width = width;
        latest.height = height;
        latest.stride = stride;
        latest.fresh = latest.fresh.saturating_add(1);
        drop(latest);
        self.ready.notify_one();
    }

    fn end(&self, end: End) {
        let mut latest = self.lock();
        latest.ended.get_or_insert(end);
        drop(latest);
        self.ready.notify_one();
    }
}

/// Per-stream state owned by the PipeWire thread.
struct StreamData {
    shared: Arc<Shared>,
    format: VideoInfoRaw,
    /// The negotiated format is one this capturer reads (BGRx / BGRA).
    usable: bool,
    /// The stream reached Paused or Streaming at least once.
    connected: bool,
}

impl StreamData {
    fn on_format(&mut self, param: &Pod) {
        let Ok((media_type, media_subtype)) = spa::param::format_utils::parse_format(param) else {
            return;
        };
        if media_type != MediaType::Video || media_subtype != MediaSubtype::Raw {
            return;
        }
        if self.format.parse(param).is_err() {
            return;
        }
        self.usable = matches!(self.format.format(), VideoFormat::BGRx | VideoFormat::BGRA);
        if !self.usable {
            self.shared.end(End::Failed(format!(
                "the compositor offered an unsupported pixel format ({:?})",
                self.format.format()
            )));
        }
    }

    fn on_buffer(&self, buffer: &mut pw::buffer::Buffer<'_>) {
        if !self.usable {
            return;
        }
        let size = self.format.size();
        let Some(data) = buffer.datas_mut().first_mut() else {
            return;
        };
        let chunk = data.chunk();
        // Size 0: no new image (e.g. only metadata changed).
        if chunk.size() == 0 || chunk.flags().contains(spa::buffer::ChunkFlags::CORRUPTED) {
            return;
        }
        let (Ok(width), Ok(height)) = (usize::try_from(size.width), usize::try_from(size.height))
        else {
            return;
        };
        let row = width.saturating_mul(4);
        let stride = usize::try_from(chunk.stride())
            .ok()
            .filter(|&stride| stride >= row)
            .unwrap_or(row);
        let offset = usize::try_from(chunk.offset()).unwrap_or(0);
        let len = stride.saturating_mul(height);
        // Mapped shared memory (MAP_BUFFERS); DMA-BUF is never negotiated
        // because no modifiers are offered.
        let Some(bytes) = data.data() else {
            return;
        };
        let Some(pixels) = bytes.get(offset..).and_then(|bytes| bytes.get(..len)) else {
            return;
        };
        self.shared.publish(pixels, size.width, size.height, stride);
    }
}

/// The stream format offered to the compositor: BGRx/BGRA in shared
/// memory, any size, `STREAM_FPS` preferred.
fn format_pod(width: u32, height: u32) -> Result<Vec<u8>, String> {
    let object = spa::pod::object!(
        SpaTypes::ObjectParamFormat,
        ParamType::EnumFormat,
        spa::pod::property!(FormatProperties::MediaType, Id, MediaType::Video),
        spa::pod::property!(FormatProperties::MediaSubtype, Id, MediaSubtype::Raw),
        spa::pod::property!(
            FormatProperties::VideoFormat,
            Choice,
            Enum,
            Id,
            VideoFormat::BGRx,
            VideoFormat::BGRx,
            VideoFormat::BGRA
        ),
        spa::pod::property!(
            FormatProperties::VideoSize,
            Choice,
            Range,
            Rectangle,
            Rectangle { width, height },
            Rectangle {
                width: 1,
                height: 1
            },
            Rectangle {
                width: 8192,
                height: 8192
            }
        ),
        spa::pod::property!(
            FormatProperties::VideoFramerate,
            Choice,
            Range,
            Fraction,
            Fraction {
                num: STREAM_FPS,
                denom: 1
            },
            Fraction { num: 0, denom: 1 },
            Fraction {
                num: 1000,
                denom: 1
            }
        ),
    );
    PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &spa::pod::Value::Object(object),
    )
    .map(|(cursor, _)| cursor.into_inner())
    .map_err(|err| format!("building the stream format: {err:?}"))
}

/// Runs the PipeWire side until `quit` fires.
fn run_stream(
    fd: OwnedFd,
    node: u32,
    size: (u32, u32),
    shared: &Arc<Shared>,
    quit: pw::channel::Receiver<()>,
) -> Result<(), String> {
    let error = |err: pw::Error| err.to_string();
    let main_loop = pw::main_loop::MainLoopRc::new(None).map_err(error)?;
    let context = pw::context::ContextRc::new(&main_loop, None).map_err(error)?;
    let core = context.connect_fd_rc(fd, None).map_err(error)?;
    let stream = pw::stream::StreamBox::new(
        &core,
        "rustremote-capture",
        pw::properties::properties! {
            *pw::keys::MEDIA_TYPE => "Video",
            *pw::keys::MEDIA_CATEGORY => "Capture",
            *pw::keys::MEDIA_ROLE => "Screen",
        },
    )
    .map_err(error)?;
    let data = StreamData {
        shared: Arc::clone(shared),
        format: VideoInfoRaw::default(),
        usable: false,
        connected: false,
    };
    let _listener = stream
        .add_local_listener_with_user_data(data)
        .state_changed(|_, data, _, new| match new {
            StreamState::Error(message) => data.shared.end(End::Failed(message)),
            StreamState::Paused | StreamState::Streaming => data.connected = true,
            StreamState::Unconnected if data.connected => data.shared.end(End::Stopped),
            StreamState::Unconnected | StreamState::Connecting => {}
        })
        .param_changed(|_, data, id, param| {
            if let Some(param) = param
                && id == ParamType::Format.as_raw()
            {
                data.on_format(param);
            }
        })
        .process(|stream, data| {
            if let Some(mut buffer) = stream.dequeue_buffer() {
                data.on_buffer(&mut buffer);
            }
        })
        .register()
        .map_err(error)?;

    let format = format_pod(size.0, size.1)?;
    let pod = Pod::from_bytes(&format).ok_or("invalid stream format")?;
    stream
        .connect(
            Direction::Input,
            Some(node),
            StreamFlags::AUTOCONNECT | StreamFlags::MAP_BUFFERS,
            &mut [pod],
        )
        .map_err(error)?;

    let quitting = main_loop.clone();
    let _quit = quit.attach(main_loop.loop_(), move |()| quitting.quit());
    main_loop.run();
    Ok(())
}

/// The tokio runtime behind every portal call. One per process: ashpd
/// keeps a single D-Bus connection for the process, bound to the runtime
/// it was first used on, so that runtime must outlive every session.
fn runtime() -> Result<&'static tokio::runtime::Runtime, CaptureError> {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    if let Some(runtime) = RUNTIME.get() {
        return Ok(runtime);
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("rr-portal")
        .enable_all()
        .build()
        .map_err(|err| os_error("starting the portal client", err))?;
    // A concurrent caller may have won the race; its runtime is used and
    // this one, never used, is dropped.
    let _ = RUNTIME.set(runtime);
    RUNTIME
        .get()
        .ok_or_else(|| os_error("starting the portal client", "no runtime"))
}

/// The portal session behind a capture.
enum Handle {
    /// The screen only.
    Cast(Session<Screencast>),
    /// The screen plus keyboard and pointer.
    Remote(Session<RemoteDesktop>),
}

/// The portal session that capture and input share. The last one to drop
/// it closes the session, which also removes the compositor's sharing
/// indicator.
struct Link {
    runtime: &'static tokio::runtime::Runtime,
    handle: Option<Handle>,
}

impl Drop for Link {
    fn drop(&mut self) {
        let Some(handle) = self.handle.take() else {
            return;
        };
        self.runtime.block_on(async {
            let close = async {
                match &handle {
                    Handle::Cast(session) => session.close().await,
                    Handle::Remote(session) => session.close().await,
                }
            };
            let _ = tokio::time::timeout(Duration::from_secs(1), close).await;
        });
    }
}

/// What the portal handed over for the picked monitor.
struct Cast {
    handle: Handle,
    /// `None` without control; otherwise the portal to inject through, or
    /// why there is none.
    input: Option<Result<RemoteDesktop, InputError>>,
    node: u32,
    position: (i32, i32),
    /// Logical size, the space pointer positions are given in.
    size: (u32, u32),
    fd: OwnedFd,
}

/// The pointer is drawn into the image when the portal can do it.
async fn cursor_mode(portal: &Screencast) -> Option<CursorMode> {
    match portal.available_cursor_modes().await {
        Ok(modes) if modes.contains(CursorMode::EMBEDDED) => Some(CursorMode::EMBEDDED),
        _ => None,
    }
}

/// One monitor, picked in the dialog.
async fn sources(portal: &Screencast) -> SelectSourcesOptions {
    SelectSourcesOptions::default()
        .set_sources(SourceType::MONITOR)
        .set_multiple(false)
        .set_cursor_mode(cursor_mode(portal).await)
}

/// The PipeWire node, position and logical size of a monitor stream.
type StreamInfo = (u32, (i32, i32), (u32, u32));

/// The [`StreamInfo`] of the picked monitor.
fn first_stream(streams: &[Stream]) -> Result<StreamInfo, CaptureError> {
    let stream = streams
        .first()
        .ok_or_else(|| os_error("Start", "the portal returned no stream"))?;
    let size = stream
        .size()
        .and_then(|(width, height)| Some((u32::try_from(width).ok()?, u32::try_from(height).ok()?)))
        .filter(|&(width, height)| width > 0 && height > 0)
        .unwrap_or((1920, 1080));
    Ok((
        stream.pipe_wire_node_id(),
        stream.position().unwrap_or((0, 0)),
        size,
    ))
}

/// The remote-desktop portal, if the compositor offers keyboard and
/// pointer through it.
async fn remote_desktop() -> Result<RemoteDesktop, InputError> {
    let unsupported = || InputError::Unsupported("the compositor offers no remote-desktop portal");
    let remote = RemoteDesktop::new().await.map_err(|_| unsupported())?;
    match remote.available_device_types().await {
        Ok(devices) if devices.contains(DEVICES) => Ok(remote),
        _ => Err(unsupported()),
    }
}

/// Asks the local user for a monitor (and, with `control`, for keyboard
/// and pointer) and opens the monitor's PipeWire stream. Without a
/// remote-desktop portal the screen is still shared, view only.
async fn start_cast(control: bool) -> Result<Cast, CaptureError> {
    let portal = Screencast::new()
        .await
        .map_err(|err| portal_error("connecting to the screen-sharing portal", err))?;
    let input = if control {
        Some(remote_desktop().await)
    } else {
        None
    };
    match input {
        Some(Ok(remote)) => start_remote(&portal, remote).await,
        Some(Err(err)) => Ok(Cast {
            input: Some(Err(err)),
            ..start_screen(&portal).await?
        }),
        None => start_screen(&portal).await,
    }
}

/// A ScreenCast session: the screen only.
async fn start_screen(portal: &Screencast) -> Result<Cast, CaptureError> {
    let session = portal
        .create_session(Default::default())
        .await
        .map_err(|err| portal_error("CreateSession", err))?;
    let options = sources(portal).await.set_persist_mode(PersistMode::DoNot);
    portal
        .select_sources(&session, options)
        .await
        .and_then(|request| request.response())
        .map_err(|err| portal_error("SelectSources", err))?;
    let streams = portal
        .start(&session, None, Default::default())
        .await
        .and_then(|request| request.response())
        .map_err(|err| portal_error("Start", err))?;
    let (node, position, size) = first_stream(streams.streams())?;
    let fd = portal
        .open_pipe_wire_remote(&session, Default::default())
        .await
        .map_err(|err| portal_error("OpenPipeWireRemote", err))?;
    Ok(Cast {
        handle: Handle::Cast(session),
        input: None,
        node,
        position,
        size,
        fd,
    })
}

/// A RemoteDesktop session carrying the ScreenCast sources: one dialog
/// for the screen, keyboard and pointer. The local user may share the
/// screen but not allow control; input is then [`InputError::Denied`].
async fn start_remote(portal: &Screencast, remote: RemoteDesktop) -> Result<Cast, CaptureError> {
    let session = remote
        .create_session(Default::default())
        .await
        .map_err(|err| portal_error("CreateSession", err))?;
    remote
        .select_devices(
            &session,
            SelectDevicesOptions::default()
                .set_devices(DEVICES)
                .set_persist_mode(PersistMode::DoNot),
        )
        .await
        .and_then(|request| request.response())
        .map_err(|err| portal_error("SelectDevices", err))?;
    portal
        .select_sources(&session, sources(portal).await)
        .await
        .and_then(|request| request.response())
        .map_err(|err| portal_error("SelectSources", err))?;
    let selected = remote
        .start(&session, None, Default::default())
        .await
        .and_then(|request| request.response())
        .map_err(|err| portal_error("Start", err))?;
    let (node, position, size) = first_stream(selected.streams())?;
    let fd = portal
        .open_pipe_wire_remote(&session, Default::default())
        .await
        .map_err(|err| portal_error("OpenPipeWireRemote", err))?;
    let input = if selected.devices().contains(DEVICES) {
        Ok(remote)
    } else {
        Err(InputError::Denied)
    };
    Ok(Cast {
        handle: Handle::Remote(session),
        input: Some(input),
        node,
        position,
        size,
        fd,
    })
}

/// Captures the monitor the local user picked in the portal dialog.
pub(crate) struct PortalCapturer {
    monitor: Monitor,
    shared: Arc<Shared>,
    quit: pw::channel::Sender<()>,
    thread: Option<JoinHandle<()>>,
    /// The session must stay open for the cast to continue.
    _link: Arc<Link>,
    /// The image being handed to the caller (swapped with the shared one).
    pixels: Vec<u8>,
}

impl PortalCapturer {
    /// Shows the compositor's dialog and starts the stream. Only id 0
    /// exists: the dialog does the choosing. With `control`, the dialog
    /// also asks for keyboard and pointer, and the second value is the
    /// input backend or why there is none.
    pub(crate) fn open(
        id: u8,
        control: bool,
    ) -> Result<(Self, Option<Result<PortalInput, InputError>>), CaptureError> {
        if id != 0 {
            return Err(CaptureError::NoSuchMonitor(id));
        }
        let runtime = runtime()?;
        let cast = runtime.block_on(async {
            tokio::time::timeout(PICK_TIMEOUT, start_cast(control))
                .await
                .unwrap_or(Err(CaptureError::Denied))
        })?;
        let Cast {
            handle,
            input,
            node,
            position,
            size,
            fd,
        } = cast;
        let link = Arc::new(Link {
            runtime,
            handle: Some(handle),
        });
        let input = input.map(|input| {
            input.map(|portal| PortalInput {
                link: Arc::clone(&link),
                portal,
                stream: node,
                size,
                notches: Notches::default(),
            })
        });

        let shared = Arc::new(Shared::default());
        let (quit, quit_rx) = pw::channel::channel::<()>();
        let thread_shared = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("rr-pipewire".to_owned())
            .spawn(move || {
                if let Err(message) = run_stream(fd, node, size, &thread_shared, quit_rx) {
                    thread_shared.end(End::Failed(message));
                }
            })
            .map_err(|err| os_error("starting the PipeWire thread", err))?;
        let capturer = Self {
            monitor: Monitor {
                width: size.0,
                height: size.1,
                left: position.0,
                top: position.1,
                ..placeholder()
            },
            shared,
            quit,
            thread: Some(thread),
            _link: link,
            pixels: Vec::new(),
        };
        Ok((capturer, input))
    }
}

/// Injects through the RemoteDesktop portal session that also carries the
/// capture. Pointer positions are in the stream's logical coordinates.
pub(crate) struct PortalInput {
    link: Arc<Link>,
    portal: RemoteDesktop,
    /// The PipeWire node of the captured monitor.
    stream: u32,
    /// The monitor's logical size.
    size: (u32, u32),
    notches: Notches,
}

impl PortalInput {
    /// Runs one portal call on the shared runtime, waiting at most
    /// `CALL_TIMEOUT`.
    fn call<'a, F>(
        &'a self,
        context: &'static str,
        call: impl FnOnce(&'a RemoteDesktop, &'a Session<RemoteDesktop>) -> F,
    ) -> Result<(), InputError>
    where
        F: Future<Output = Result<(), ashpd::Error>> + 'a,
    {
        let Some(Handle::Remote(session)) = &self.link.handle else {
            return Err(InputError::Unsupported("the portal session has no input"));
        };
        let future = call(&self.portal, session);
        let message = match self
            .link
            .runtime
            .block_on(tokio::time::timeout(CALL_TIMEOUT, future))
        {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(err)) => err.to_string(),
            Err(_) => "the portal did not answer".to_owned(),
        };
        Err(InputError::Os {
            context,
            code: 0,
            message,
        })
    }
}

/// A logical coordinate: `coord / 65536` of the way across `size`.
fn logical(coord: u16, size: u32) -> f64 {
    f64::from(coord) * f64::from(size) / 65_536.0
}

const fn key_state(down: bool) -> KeyState {
    if down {
        KeyState::Pressed
    } else {
        KeyState::Released
    }
}

impl InputBackend for PortalInput {
    fn key(&mut self, key: KeyCode, down: bool) -> Result<(), InputError> {
        let Some(code) = keymap::evdev(key) else {
            return Ok(());
        };
        self.call("NotifyKeyboardKeycode", |portal, session| {
            portal.notify_keyboard_keycode(
                session,
                i32::from(code),
                key_state(down),
                Default::default(),
            )
        })
    }

    fn move_to(&mut self, x: u16, y: u16) -> Result<(), InputError> {
        let (stream, (width, height)) = (self.stream, self.size);
        self.call("NotifyPointerMotionAbsolute", |portal, session| {
            portal.notify_pointer_motion_absolute(
                session,
                stream,
                logical(x, width),
                logical(y, height),
                Default::default(),
            )
        })
    }

    fn button(&mut self, button: MouseButton, down: bool) -> Result<(), InputError> {
        let code = i32::from(keymap::evdev_button(button));
        self.call("NotifyPointerButton", |portal, session| {
            portal.notify_pointer_button(session, code, key_state(down), Default::default())
        })
    }

    fn wheel(&mut self, dx: i32, dy: i32) -> Result<(), InputError> {
        let (x, y) = self.notches.add(dx, dy);
        // The portal's vertical axis grows downwards.
        if y != 0 {
            self.call("NotifyPointerAxisDiscrete", |portal, session| {
                portal.notify_pointer_axis_discrete(
                    session,
                    Axis::Vertical,
                    y.saturating_neg(),
                    Default::default(),
                )
            })?;
        }
        if x != 0 {
            self.call("NotifyPointerAxisDiscrete", |portal, session| {
                portal.notify_pointer_axis_discrete(
                    session,
                    Axis::Horizontal,
                    x,
                    Default::default(),
                )
            })?;
        }
        Ok(())
    }

    fn repeats_by_itself(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        "RemoteDesktop portal"
    }
}

impl ScreenCapturer for PortalCapturer {
    fn monitor(&self) -> &Monitor {
        &self.monitor
    }

    fn capture(
        &mut self,
        timeout: Duration,
        on_frame: &mut dyn FnMut(Frame<'_>),
    ) -> Result<bool, CaptureError> {
        let deadline = Instant::now() + timeout;
        let mut latest = self.shared.lock();
        while latest.fresh == 0 && latest.ended.is_none() {
            let now = Instant::now();
            if now >= deadline {
                return Ok(false);
            }
            latest = self
                .shared
                .ready
                .wait_timeout(latest, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        match latest.ended.take() {
            Some(End::Stopped) => return Err(CaptureError::Denied),
            Some(End::Failed(message)) => return Err(os_error("PipeWire stream", message)),
            None => {}
        }
        std::mem::swap(&mut self.pixels, &mut latest.pixels);
        let (width, height, stride) = (latest.width, latest.height, latest.stride);
        let accumulated = std::mem::take(&mut latest.fresh);
        let copy = latest.copy;
        drop(latest);
        // The copy happened on the PipeWire thread; report its cost as the
        // capture time, not how long the image waited for this call.
        let now = Instant::now();
        let acquired = now.checked_sub(copy).unwrap_or(now);
        (self.monitor.width, self.monitor.height) = (width, height);
        on_frame(Frame {
            width,
            height,
            stride,
            bgra: &self.pixels,
            accumulated,
            acquired,
        });
        Ok(true)
    }
}

impl Drop for PortalCapturer {
    fn drop(&mut self) {
        let _ = self.quit.send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        // The session closes when `_link` drops, unless input still uses it.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_format_serializes() {
        let format = format_pod(1920, 1080).unwrap();
        assert!(Pod::from_bytes(&format).is_some());
    }

    #[test]
    fn the_dialog_decides_the_monitor() {
        assert_eq!(monitors(), [placeholder()]);
        assert!(matches!(
            PortalCapturer::open(1, false),
            Err(CaptureError::NoSuchMonitor(1))
        ));
    }

    #[test]
    fn logical_coordinates_stay_on_the_monitor() {
        assert!(logical(0, 1920).abs() < f64::EPSILON);
        assert!((logical(32_768, 1920) - 960.0).abs() < f64::EPSILON);
        let last = logical(u16::MAX, 1920);
        assert!(last < 1920.0 && last > 1919.9);
    }
}
