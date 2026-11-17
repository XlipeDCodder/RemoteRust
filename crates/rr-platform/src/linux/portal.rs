//! Wayland screen capture (blueprint v2 §3, §8.3), M2 CPU path: the
//! xdg-desktop-portal ScreenCast interface lets the local user pick a
//! monitor in the compositor's own dialog, then images arrive over
//! PipeWire as BGRx in shared memory.
//!
//! Compositors send an image only when the screen changed, so a static
//! screen costs a blocking wait and nothing else. The pointer is left out
//! of the image when the portal allows it; it travels separately (M3).

use std::os::fd::OwnedFd;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use ashpd::desktop::screencast::{CursorMode, Screencast, SelectSourcesOptions, SourceType};
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

/// The name the single portal "monitor" goes by: the real choice happens
/// in the compositor's dialog.
const PICKED: &str = "picked in the sharing dialog";
/// Longest wait for the local user to pick a screen.
const PICK_TIMEOUT: Duration = Duration::from_secs(60);
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

/// What the portal handed over for the picked monitor.
struct Cast {
    session: Session<Screencast>,
    node: u32,
    position: (i32, i32),
    size: (u32, u32),
    fd: OwnedFd,
}

/// Asks the local user for a monitor and opens its PipeWire stream.
async fn start_cast() -> Result<Cast, CaptureError> {
    let portal = Screencast::new()
        .await
        .map_err(|err| portal_error("connecting to the screen-sharing portal", err))?;
    let session = portal
        .create_session(Default::default())
        .await
        .map_err(|err| portal_error("CreateSession", err))?;
    let cursor = match portal.available_cursor_modes().await {
        Ok(modes) if modes.contains(CursorMode::HIDDEN) => CursorMode::HIDDEN,
        _ => CursorMode::EMBEDDED,
    };
    portal
        .select_sources(
            &session,
            SelectSourcesOptions::default()
                .set_sources(SourceType::MONITOR)
                .set_multiple(false)
                .set_cursor_mode(cursor)
                .set_persist_mode(PersistMode::DoNot),
        )
        .await
        .and_then(|request| request.response())
        .map_err(|err| portal_error("SelectSources", err))?;
    let streams = portal
        .start(&session, None, Default::default())
        .await
        .and_then(|request| request.response())
        .map_err(|err| portal_error("Start", err))?;
    let stream = streams
        .streams()
        .first()
        .ok_or_else(|| os_error("Start", "the portal returned no stream"))?;
    let node = stream.pipe_wire_node_id();
    let position = stream.position().unwrap_or((0, 0));
    let size = stream
        .size()
        .and_then(|(width, height)| Some((u32::try_from(width).ok()?, u32::try_from(height).ok()?)))
        .unwrap_or((1920, 1080));
    let fd = portal
        .open_pipe_wire_remote(&session, Default::default())
        .await
        .map_err(|err| portal_error("OpenPipeWireRemote", err))?;
    Ok(Cast {
        session,
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
    /// Drives the portal's D-Bus connection; the session must stay open
    /// for the cast to continue.
    runtime: tokio::runtime::Runtime,
    session: Option<Session<Screencast>>,
    /// The image being handed to the caller (swapped with the shared one).
    pixels: Vec<u8>,
}

impl PortalCapturer {
    /// Shows the compositor's dialog and starts the stream. Only id 0
    /// exists: the dialog does the choosing.
    pub(crate) fn open(id: u8) -> Result<Self, CaptureError> {
        if id != 0 {
            return Err(CaptureError::NoSuchMonitor(id));
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("rr-portal")
            .enable_all()
            .build()
            .map_err(|err| os_error("starting the portal client", err))?;
        let cast = runtime.block_on(async {
            tokio::time::timeout(PICK_TIMEOUT, start_cast())
                .await
                .unwrap_or(Err(CaptureError::Denied))
        })?;

        let shared = Arc::new(Shared::default());
        let (quit, quit_rx) = pw::channel::channel::<()>();
        let thread_shared = Arc::clone(&shared);
        let Cast {
            session,
            node,
            position,
            size,
            fd,
        } = cast;
        let thread = std::thread::Builder::new()
            .name("rr-pipewire".to_owned())
            .spawn(move || {
                if let Err(message) = run_stream(fd, node, size, &thread_shared, quit_rx) {
                    thread_shared.end(End::Failed(message));
                }
            })
            .map_err(|err| os_error("starting the PipeWire thread", err))?;
        Ok(Self {
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
            runtime,
            session: Some(session),
            pixels: Vec::new(),
        })
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
        // Closing the session removes the compositor's sharing indicator.
        if let Some(session) = self.session.take() {
            self.runtime.block_on(async {
                let _ = tokio::time::timeout(Duration::from_secs(1), session.close()).await;
            });
        }
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
            PortalCapturer::open(1),
            Err(CaptureError::NoSuchMonitor(1))
        ));
    }
}
