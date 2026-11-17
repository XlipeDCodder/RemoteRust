//! The session window (blueprint v2 §8.6): the winit event loop runs on the
//! main thread, the network on the tokio runtime, decoding on its own
//! thread. A frame is drawn as soon as it is decoded.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use rr_net::{RemoteEvent, RemoteSession, SessionControl, StatsSource};
use rr_proto::DisconnectReason;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use winit::application::ApplicationHandler;
use winit::dpi::{PhysicalPosition, PhysicalSize};
use winit::event::{ElementState, KeyEvent, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop, EventLoopProxy};
use winit::keyboard::{KeyCode, PhysicalKey};
use winit::window::{Fullscreen, Window, WindowId};

use crate::overlay::Overlay;
use crate::render::{OverlayFrame, Renderer};
use crate::video::Pipeline;

/// How often the overlay statistics are refreshed.
const STATS_PERIOD: Duration = Duration::from_secs(1);

/// Events sent to the window from other threads.
#[derive(Debug)]
pub enum UserEvent {
    /// A decoded picture waits in the mailbox.
    Frame,
    /// The Agent now encodes with this encoder.
    Encoder(String),
    /// The session is over, with the Agent's reason if it gave one.
    Ended(Option<DisconnectReason>),
    /// The video stream broke.
    VideoFailed(String),
}

/// Window placement.
#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    /// Local display to open on (index in the system's list).
    pub display: Option<usize>,
    /// Start in borderless full screen.
    pub fullscreen: bool,
}

/// Why the window closed.
#[derive(Debug)]
pub enum Outcome {
    /// The user closed the window.
    Closed,
    /// The session ended, with the Agent's reason if it gave one.
    Ended(Option<DisconnectReason>),
    /// Something failed.
    Failed(String),
}

/// Totals for the whole session.
#[derive(Debug)]
pub struct Summary {
    duration: Duration,
    received: u64,
    bytes: u64,
    shown: u64,
    folded: u64,
    replaced: u64,
    discarded: u64,
    errors: u64,
}

impl fmt::Display for Summary {
    #[allow(clippy::cast_precision_loss)] // display only
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let seconds = self.duration.as_secs_f64().max(0.001);
        writeln!(
            f,
            "  {:.1} s: {} frames received ({:.1} MiB, {:.2} Mbit/s average), {} shown ({:.1} fps)",
            seconds,
            self.received,
            self.bytes as f64 / (1024.0 * 1024.0),
            self.bytes as f64 * 8.0 / seconds / 1_000_000.0,
            self.shown,
            self.shown as f64 / seconds,
        )?;
        write!(
            f,
            "  updates folded by the Agent {}, pictures replaced before drawing {}, \
             frames discarded waiting for a keyframe {}, decode errors {}",
            self.folded, self.replaced, self.discarded, self.errors
        )
    }
}

/// Shows `session` in a window until either side ends it.
pub fn run(
    runtime: &Runtime,
    mut session: RemoteSession,
    path: String,
    options: Options,
) -> anyhow::Result<(Outcome, Summary)> {
    let started = Instant::now();
    let event_loop = EventLoop::<UserEvent>::with_user_event()
        .build()
        .context("cannot start the window system")?;
    let proxy = event_loop.create_proxy();
    let video = session
        .take_video()
        .context("the video stream was already taken")?;
    let events = session
        .take_events()
        .context("the session events were already taken")?;
    let control = session.control();
    let pipeline = Pipeline::start(runtime.handle(), video, control.clone(), proxy.clone())?;
    runtime.spawn(forward_events(events, proxy));

    let grant = session.grant();
    let picture_size = grant
        .monitors
        .iter()
        .find(|monitor| monitor.id == grant.monitor)
        .map(|monitor| (u32::from(monitor.width), u32::from(monitor.height)))
        // 0 × 0: the size is unknown until the first frame (the Agent's
        // user picks the screen in a system dialog).
        .filter(|&(width, height)| width > 0 && height > 0);
    let mut app = App {
        title: format!("{} - RustRemote (view only)", session.agent_name()),
        options,
        picture_size,
        window: None,
        renderer: None,
        egui: egui::Context::default(),
        egui_state: None,
        overlay: Overlay::new(session.agent_name(), path),
        pipeline: &pipeline,
        stats: session.stats_source(),
        control,
        next_tick: Instant::now(),
        outcome: None,
        video_error: None,
        shown: 0,
    };
    let result = event_loop.run_app(&mut app);
    let outcome = app.outcome.take().unwrap_or(Outcome::Closed);
    let shown = app.shown;
    // Close the window first, then end the session politely.
    drop(app);
    runtime.block_on(session.close());
    let counters = &pipeline.counters;
    let summary = Summary {
        duration: started.elapsed(),
        received: counters.frames.load(Ordering::Relaxed),
        bytes: counters.bytes.load(Ordering::Relaxed),
        shown,
        folded: counters.folded.load(Ordering::Relaxed),
        replaced: pipeline.mailbox.dropped(),
        discarded: counters.discarded.load(Ordering::Relaxed),
        errors: counters.errors.load(Ordering::Relaxed),
    };
    pipeline.stop();
    result.context("window system error")?;
    Ok((outcome, summary))
}

async fn forward_events(mut events: mpsc::Receiver<RemoteEvent>, proxy: EventLoopProxy<UserEvent>) {
    while let Some(event) = events.recv().await {
        let event = match event {
            RemoteEvent::Encoder(name) => UserEvent::Encoder(name),
            RemoteEvent::Ended(reason) => UserEvent::Ended(reason),
        };
        if proxy.send_event(event).is_err() {
            return;
        }
    }
    let _ = proxy.send_event(UserEvent::Ended(None));
}

struct App<'a> {
    title: String,
    options: Options,
    picture_size: Option<(u32, u32)>,
    window: Option<Arc<Window>>,
    renderer: Option<Renderer>,
    egui: egui::Context,
    egui_state: Option<egui_winit::State>,
    overlay: Overlay,
    pipeline: &'a Pipeline,
    stats: StatsSource,
    control: SessionControl,
    next_tick: Instant,
    outcome: Option<Outcome>,
    video_error: Option<String>,
    /// Pictures presented so far.
    shown: u64,
}

impl App<'_> {
    fn open(&mut self, event_loop: &ActiveEventLoop) -> anyhow::Result<()> {
        let monitor = match self.options.display {
            Some(index) => Some(
                event_loop
                    .available_monitors()
                    .nth(index)
                    .with_context(|| format!("there is no local display {index}"))?,
            ),
            // Wayland has no primary monitor: size the window for the
            // first one (the compositor places it anyway).
            None => event_loop
                .primary_monitor()
                .or_else(|| event_loop.available_monitors().next()),
        };
        let mut attributes = Window::default_attributes().with_title(self.title.clone());
        if let Some(monitor) = &monitor {
            let area = monitor.size();
            let (width, height) = initial_size(self.picture_size, (area.width, area.height));
            let origin = monitor.position();
            let offset = |free: u32| i32::try_from(free / 2).unwrap_or(0);
            attributes = attributes
                .with_inner_size(PhysicalSize::new(width, height))
                .with_position(PhysicalPosition::new(
                    origin
                        .x
                        .saturating_add(offset(area.width.saturating_sub(width))),
                    origin
                        .y
                        .saturating_add(offset(area.height.saturating_sub(height))),
                ));
        }
        if self.options.fullscreen {
            attributes = attributes.with_fullscreen(Some(Fullscreen::Borderless(monitor)));
        }
        let window = Arc::new(
            event_loop
                .create_window(attributes)
                .context("cannot open the window")?,
        );
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor::new_with_display_handle(
            Box::new(event_loop.owned_display_handle()),
        ));
        let renderer = pollster::block_on(Renderer::new(instance, Arc::clone(&window)))?;
        #[allow(clippy::cast_possible_truncation)] // a scale factor fits an f32
        let scale = window.scale_factor() as f32;
        let state = egui_winit::State::new(
            self.egui.clone(),
            egui::ViewportId::ROOT,
            &window,
            Some(scale),
            window.theme(),
            Some(renderer.max_texture_side()),
        );
        tracing::info!(display = renderer.description(), "window open");
        self.overlay.set_display(renderer.description());
        self.egui_state = Some(state);
        self.renderer = Some(renderer);
        self.window = Some(window);
        Ok(())
    }

    /// Draws the newest decoded picture, if there is one. Until the window
    /// is ready, pictures stay in the mailbox (a static screen may send
    /// only one).
    fn show_frame(&mut self) {
        let Some(renderer) = &mut self.renderer else {
            return;
        };
        let Some(frame) = self.pipeline.mailbox.take() else {
            return;
        };
        renderer.upload(&frame.picture);
        if self.redraw() {
            self.shown = self.shown.saturating_add(1);
            self.overlay.on_frame(&frame, frame.decoded_at.elapsed());
        }
        self.pipeline.mailbox.recycle(frame);
    }

    /// Draws the window. Returns `false` if nothing could be shown.
    fn redraw(&mut self) -> bool {
        let (Some(window), Some(renderer)) = (&self.window, &mut self.renderer) else {
            return false;
        };
        let overlay = match &mut self.egui_state {
            Some(state) if self.overlay.visible => {
                let input = state.take_egui_input(window);
                let output = self.egui.run_ui(input, |ui| self.overlay.ui(ui));
                state.handle_platform_output(window, output.platform_output);
                Some(OverlayFrame {
                    primitives: self.egui.tessellate(output.shapes, output.pixels_per_point),
                    textures: output.textures_delta,
                    pixels_per_point: output.pixels_per_point,
                })
            }
            _ => None,
        };
        renderer.render(overlay)
    }

    fn finish(&mut self, event_loop: &ActiveEventLoop, outcome: Outcome) {
        self.outcome.get_or_insert(outcome);
        event_loop.exit();
    }
}

impl ApplicationHandler<UserEvent> for App<'_> {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.window.is_some() {
            return;
        }
        match self.open(event_loop) {
            Ok(()) => self.show_frame(),
            Err(err) => self.finish(event_loop, Outcome::Failed(format!("{err:#}"))),
        }
    }

    fn window_event(&mut self, event_loop: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        let Some(window) = self.window.clone() else {
            return;
        };
        if let Some(state) = &mut self.egui_state {
            let response = state.on_window_event(&window, &event);
            if response.repaint && self.overlay.visible {
                window.request_redraw();
            }
        }
        match event {
            WindowEvent::CloseRequested => self.finish(event_loop, Outcome::Closed),
            WindowEvent::Resized(size) => {
                if let Some(renderer) = &mut self.renderer {
                    renderer.resize(size.width, size.height);
                }
                window.request_redraw();
            }
            WindowEvent::RedrawRequested => {
                self.redraw();
            }
            WindowEvent::KeyboardInput {
                event:
                    KeyEvent {
                        physical_key: PhysicalKey::Code(code),
                        state: ElementState::Pressed,
                        repeat: false,
                        ..
                    },
                ..
            } => match code {
                KeyCode::F1 => {
                    self.overlay.visible = !self.overlay.visible;
                    window.request_redraw();
                }
                KeyCode::F11 => {
                    let next = if window.fullscreen().is_some() {
                        None
                    } else {
                        Some(Fullscreen::Borderless(window.current_monitor()))
                    };
                    window.set_fullscreen(next);
                }
                _ => {}
            },
            _ => {}
        }
    }

    fn user_event(&mut self, event_loop: &ActiveEventLoop, event: UserEvent) {
        match event {
            UserEvent::Frame => self.show_frame(),
            UserEvent::Encoder(name) => {
                self.overlay.set_encoder(name);
                if let (Some(window), true) = (&self.window, self.overlay.visible) {
                    window.request_redraw();
                }
            }
            UserEvent::Ended(reason) => {
                // When the video failed first, its error is the better
                // explanation for an ending without a reason.
                let outcome = match (reason, self.video_error.take()) {
                    (None, Some(error)) => Outcome::Failed(error),
                    (reason, _) => Outcome::Ended(reason),
                };
                self.finish(event_loop, outcome);
            }
            UserEvent::VideoFailed(error) => {
                // A closing connection also ends the control stream, which
                // reports the reason; otherwise end the session here.
                self.video_error.get_or_insert(error);
                self.control.close();
            }
        }
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        if let Some(failure) = self.renderer.as_ref().and_then(Renderer::take_failure) {
            self.finish(event_loop, Outcome::Failed(failure));
            return;
        }
        let now = Instant::now();
        if now >= self.next_tick {
            self.overlay.tick(
                &self.pipeline.counters,
                self.pipeline.mailbox.dropped(),
                self.stats.path_stats(),
            );
            self.next_tick = now.checked_add(STATS_PERIOD).unwrap_or(now);
            if let (Some(window), true) = (&self.window, self.overlay.visible) {
                window.request_redraw();
            }
        }
        event_loop.set_control_flow(ControlFlow::WaitUntil(self.next_tick));
    }
}

/// Initial inner window size: the remote picture at 1:1 when it fits in
/// 90% of the local display, else scaled down with the same aspect ratio.
fn initial_size(picture: Option<(u32, u32)>, display: (u32, u32)) -> (u32, u32) {
    let (width, height) = picture.unwrap_or((1280, 720));
    let (width, height) = (u64::from(width.max(2)), u64::from(height.max(2)));
    let max_width = u64::from(display.0) * 9 / 10;
    let max_height = u64::from(display.1) * 9 / 10;
    let (width, height) = if width <= max_width && height <= max_height {
        (width, height)
    } else if width * max_height > height * max_width {
        // Wider than the display area: width is the limit.
        (max_width, height * max_width / width)
    } else {
        (width * max_height / height, max_height)
    };
    let clamp = |value: u64| u32::try_from(value.max(64)).unwrap_or(u32::MAX);
    (clamp(width), clamp(height))
}

#[cfg(test)]
mod tests {
    use super::initial_size;

    #[test]
    fn initial_size_fits_the_display() {
        assert_eq!(initial_size(Some((1280, 720)), (1920, 1080)), (1280, 720));
        assert_eq!(initial_size(Some((1920, 1080)), (1920, 1080)), (1728, 972));
        assert_eq!(initial_size(Some((1920, 1200)), (1920, 1080)), (1555, 972));
        assert_eq!(initial_size(Some((3840, 1080)), (1920, 1080)), (1728, 486));
        assert_eq!(initial_size(None, (800, 600)), (720, 405));
    }
}
