//! The session window (blueprint v2 §8.6): the winit event loop runs on the
//! main thread, the network on the tokio runtime, decoding on its own
//! thread. A frame is drawn as soon as it is decoded.
//!
//! With control, the keyboard and mouse go to the Agent ([`crate::input`]).
//! Every key goes there, and on Windows a low-level hook takes system
//! shortcuts too (Alt+Tab, the Windows key) while the window has the focus.
//! The Viewer's own functions then live in the toolbar at the top center
//! ([`crate::toolbar`]). Viewing only, F1 and F11 also work locally.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use rr_net::{CursorReceiver, RemoteEvent, RemoteSession, SessionControl, StatsSource};
use rr_platform::hook::KeyboardHook;
use rr_platform::input::InputError;
use rr_proto::{CursorMsg, DisconnectReason, KeyCode as RemoteKey};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use winit::application::ApplicationHandler;
use winit::dpi::{PhysicalPosition, PhysicalSize};
use winit::event::{ElementState, KeyEvent, MouseButton, MouseScrollDelta, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop, EventLoopProxy};
use winit::keyboard::{KeyCode, PhysicalKey};
use winit::window::{CursorIcon, Fullscreen, Window, WindowId};

use crate::cursor::{RemoteCursor, Sprite};
use crate::input::{self, RemoteInput};
use crate::overlay::Overlay;
use crate::render::{OverlayFrame, PictureRect, Renderer};
use crate::toolbar::{Action, Toolbar};
use crate::video::Pipeline;

/// How often the overlay statistics are refreshed.
const STATS_PERIOD: Duration = Duration::from_secs(1);
/// Longest wait for held input to be released on the Agent when closing.
const INPUT_DRAIN: Duration = Duration::from_millis(500);

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
    /// A key taken by the keyboard hook (Windows, with control).
    Key(RemoteKey, bool),
    /// A pointer update from the Agent.
    Cursor(CursorMsg),
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
    runtime.spawn(forward_events(events, proxy.clone()));
    let cursor_task = session
        .take_cursor()
        .map(|cursor| runtime.spawn(forward_cursor(cursor, proxy.clone())));

    // Only present when the Agent granted control.
    let monitor = session.grant().monitor;
    let (input, input_task) = match session.take_input() {
        Some(sender) => {
            let (queue, outgoing) = mpsc::unbounded_channel();
            (
                Some(RemoteInput::new(queue, monitor)),
                Some(runtime.spawn(input::send(sender, outgoing))),
            )
        }
        None => (None, None),
    };
    let hook = input.as_ref().and_then(|_| install_hook(proxy.clone()));
    let grant = session.grant();
    let picture_size = grant
        .monitors
        .iter()
        .find(|monitor| monitor.id == grant.monitor)
        .map(|monitor| (u32::from(monitor.width), u32::from(monitor.height)))
        // 0 × 0: the size is unknown until the first frame (the Agent's
        // user picks the screen in a system dialog).
        .filter(|&(width, height)| width > 0 && height > 0);
    let mode = if input.is_some() {
        "control"
    } else {
        "view only"
    };
    let mut app = App {
        title: format!("{} - RustRemote ({mode})", session.agent_name()),
        options,
        picture_size,
        window: None,
        renderer: None,
        egui: egui::Context::default(),
        egui_state: None,
        overlay: Overlay::new(session.agent_name(), path, input.is_some()),
        pipeline: &pipeline,
        stats: session.stats_source(),
        control,
        next_tick: Instant::now(),
        outcome: None,
        video_error: None,
        shown: 0,
        input,
        hook,
        cursor: RemoteCursor::default(),
        toolbar: Toolbar::default(),
        pointer: None,
        applied_cursor: None,
    };
    let result = event_loop.run_app(&mut app);
    let outcome = app.outcome.take().unwrap_or(Outcome::Closed);
    let shown = app.shown;
    // Close the window first (releasing anything held on the Agent and
    // ending the input stream), then end the session politely.
    drop(app);
    if let Some(task) = input_task {
        let _ = runtime.block_on(tokio::time::timeout(INPUT_DRAIN, task));
    }
    if let Some(task) = cursor_task {
        task.abort();
    }
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

/// Passes pointer updates to the window. The Agent may never open the
/// stream (Wayland draws the pointer into the video).
async fn forward_cursor(mut cursor: CursorReceiver, proxy: EventLoopProxy<UserEvent>) {
    loop {
        match cursor.recv().await {
            Ok(msg) => {
                if proxy.send_event(UserEvent::Cursor(msg)).is_err() {
                    return;
                }
            }
            Err(err) => {
                tracing::debug!(error = %err, "cursor stream closed");
                return;
            }
        }
    }
}

/// The keyboard hook, where the platform has one (Windows).
fn install_hook(proxy: EventLoopProxy<UserEvent>) -> Option<KeyboardHook> {
    let hook = KeyboardHook::install(move |key, down| {
        let _ = proxy.send_event(UserEvent::Key(key, down));
    });
    match hook {
        Ok(hook) => Some(hook),
        Err(InputError::Unsupported(reason)) => {
            tracing::debug!(reason, "system shortcuts stay local");
            None
        }
        Err(err) => {
            tracing::warn!(error = %err, "cannot capture system shortcuts; they stay local");
            None
        }
    }
}

/// What the local pointer looks like over the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalPointer {
    Arrow,
    Hidden,
    Remote,
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
    /// Present only with control.
    input: Option<RemoteInput>,
    /// Present only with control, on Windows.
    hook: Option<KeyboardHook>,
    cursor: RemoteCursor,
    toolbar: Toolbar,
    /// The local pointer, in window pixels, while it is over the window.
    pointer: Option<(f64, f64)>,
    /// The local pointer set last; `None` forces setting it again.
    applied_cursor: Option<LocalPointer>,
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
    fn show_frame(&mut self, event_loop: &ActiveEventLoop) {
        let Some(renderer) = &mut self.renderer else {
            return;
        };
        let Some(frame) = self.pipeline.mailbox.take() else {
            return;
        };
        renderer.upload(&frame.picture);
        let (shown, action) = self.redraw();
        if shown {
            self.shown = self.shown.saturating_add(1);
            self.overlay.on_frame(&frame, frame.decoded_at.elapsed());
        }
        self.pipeline.mailbox.recycle(frame);
        self.act(event_loop, action);
    }

    /// Draws the window. Returns `false` if nothing could be shown, and
    /// what was clicked in the toolbar.
    fn redraw(&mut self) -> (bool, Option<Action>) {
        let (Some(window), Some(renderer)) = (&self.window, &mut self.renderer) else {
            return (false, None);
        };
        let mut action = None;
        let picture = renderer.picture_rect();
        let sprite = if self.input.is_none() {
            self.cursor.sprite(&self.egui)
        } else {
            None
        };
        let overlay = match &mut self.egui_state {
            Some(state) => {
                let input = state.take_egui_input(window);
                let mode = if self.input.is_some() {
                    "Control"
                } else {
                    "View only"
                };
                let fullscreen = window.fullscreen().is_some();
                let output = self.egui.run_ui(input, |ui| {
                    if self.overlay.visible {
                        self.overlay.ui(ui);
                    }
                    if let (Some(sprite), Some(picture)) = (&sprite, picture) {
                        paint_sprite(ui.ctx(), sprite, picture);
                    }
                    action = self
                        .toolbar
                        .ui(ui.ctx(), mode, self.overlay.visible, fullscreen);
                });
                // The platform output (cursor icon, clipboard, IME) is not
                // applied: this window manages its own pointer.
                Some(OverlayFrame {
                    primitives: self.egui.tessellate(output.shapes, output.pixels_per_point),
                    textures: output.textures_delta,
                    pixels_per_point: output.pixels_per_point,
                })
            }
            None => None,
        };
        (renderer.render(overlay), action)
    }

    fn act(&mut self, event_loop: &ActiveEventLoop, action: Option<Action>) {
        let Some(window) = self.window.clone() else {
            return;
        };
        match action {
            Some(Action::ToggleStats) => self.overlay.visible = !self.overlay.visible,
            Some(Action::ToggleFullscreen) => toggle_fullscreen(&window),
            Some(Action::Disconnect) => {
                self.finish(event_loop, Outcome::Closed);
                return;
            }
            None => return,
        }
        window.request_redraw();
    }

    fn finish(&mut self, event_loop: &ActiveEventLoop, outcome: Outcome) {
        self.outcome.get_or_insert(outcome);
        event_loop.exit();
    }

    /// The local pointer in egui points, and the window width in points.
    #[allow(clippy::cast_possible_truncation)] // window coordinates fit an f32
    fn pointer_points(&self) -> (Option<egui::Pos2>, f32) {
        let Some(window) = &self.window else {
            return (None, 0.0);
        };
        let scale = window.scale_factor();
        let width = (f64::from(window.inner_size().width) / scale) as f32;
        let pointer = self
            .pointer
            .map(|(x, y)| egui::pos2((x / scale) as f32, (y / scale) as f32));
        (pointer, width)
    }

    fn over_toolbar(&self) -> bool {
        let (pointer, width) = self.pointer_points();
        pointer.is_some_and(|pointer| self.toolbar.contains(pointer, width))
    }

    /// Whether the local pointer is over the remote picture (not over the
    /// toolbar or the black bars).
    fn over_picture(&self) -> bool {
        let (Some(pointer), Some(picture)) = (
            self.pointer,
            self.renderer.as_ref().and_then(Renderer::picture_rect),
        ) else {
            return false;
        };
        !self.over_toolbar() && input::picture_coords(pointer, picture, false).is_some()
    }

    /// Shows the remote pointer's shape over the picture (with control),
    /// hidden when the Agent hides it, and the usual arrow elsewhere.
    fn update_local_pointer(&mut self, event_loop: &ActiveEventLoop) {
        let Some(window) = self.window.clone() else {
            return;
        };
        let wanted = if self.input.is_some() && self.cursor.has_shape() && self.over_picture() {
            if self.cursor.visible() {
                LocalPointer::Remote
            } else {
                LocalPointer::Hidden
            }
        } else {
            LocalPointer::Arrow
        };
        if self.applied_cursor == Some(wanted) {
            return;
        }
        match wanted {
            LocalPointer::Remote => {
                match self.cursor.native(event_loop) {
                    Some(cursor) => window.set_cursor(cursor),
                    None => window.set_cursor(CursorIcon::Default),
                }
                window.set_cursor_visible(true);
            }
            LocalPointer::Hidden => window.set_cursor_visible(false),
            LocalPointer::Arrow => {
                window.set_cursor(CursorIcon::Default);
                window.set_cursor_visible(true);
            }
        }
        self.applied_cursor = Some(wanted);
    }

    fn on_focus(&mut self, focused: bool) {
        if let Some(hook) = &self.hook {
            hook.set_active(focused);
        }
        if !focused && let Some(input) = &mut self.input {
            input.release_all(Instant::now());
        }
    }

    fn on_key(&mut self, window: &Window, event: &KeyEvent) {
        let PhysicalKey::Code(code) = event.physical_key else {
            return;
        };
        let down = event.state == ElementState::Pressed;
        match &mut self.input {
            Some(input) => {
                // With the hook, keys arrive as `UserEvent::Key` instead.
                if self.hook.is_none()
                    && let Some(key) = input::key_code(code)
                {
                    input.key(key, down, Instant::now());
                }
            }
            None if down && !event.repeat => match code {
                KeyCode::F1 => {
                    self.overlay.visible = !self.overlay.visible;
                    window.request_redraw();
                }
                KeyCode::F11 => toggle_fullscreen(window),
                _ => {}
            },
            None => {}
        }
    }

    fn on_pointer(
        &mut self,
        event_loop: &ActiveEventLoop,
        window: &Window,
        position: Option<PhysicalPosition<f64>>,
    ) {
        self.pointer = position.map(|position| (position.x, position.y));
        let (points, width) = self.pointer_points();
        if self.toolbar.pointer_moved(points, width) {
            window.request_redraw();
        }
        self.update_local_pointer(event_loop);
        let over_toolbar = self.over_toolbar();
        let picture = self.renderer.as_ref().and_then(Renderer::picture_rect);
        let (Some(input), Some(pointer), Some(picture)) = (&mut self.input, self.pointer, picture)
        else {
            return;
        };
        // A drag keeps going, pinned to the picture's edge, wherever the
        // pointer goes.
        let dragging = input.dragging();
        if over_toolbar && !dragging {
            return;
        }
        if let Some((x, y)) = input::picture_coords(pointer, picture, dragging) {
            input.move_to(x, y, Instant::now());
        }
    }

    fn on_button(&mut self, state: ElementState, button: MouseButton) {
        let Some(button) = input::mouse_button(button) else {
            return;
        };
        let down = state == ElementState::Pressed;
        // Presses count only over the picture; releases always do, so
        // nothing stays pressed on the Agent.
        let over_picture = self.over_picture();
        if let Some(input) = &mut self.input
            && (!down || over_picture)
        {
            input.button(button, down, Instant::now());
        }
    }

    fn on_wheel(&mut self, delta: MouseScrollDelta) {
        if !self.over_picture() {
            return;
        }
        let Some(input) = &mut self.input else {
            return;
        };
        // winit: positive values move the content right and down, that is
        // scroll left and up; the protocol's dx > 0 scrolls right.
        let now = Instant::now();
        match delta {
            MouseScrollDelta::LineDelta(x, y) => {
                input.wheel_notches(-f64::from(x), f64::from(y), now);
            }
            MouseScrollDelta::PixelDelta(position) => {
                input.wheel_pixels(-position.x, position.y, now);
            }
        }
    }
}

fn toggle_fullscreen(window: &Window) {
    let next = if window.fullscreen().is_some() {
        None
    } else {
        Some(Fullscreen::Borderless(window.current_monitor()))
    };
    window.set_fullscreen(next);
}

/// Paints the remote pointer over the picture, scaled like the picture.
fn paint_sprite(ctx: &egui::Context, sprite: &Sprite, picture: PictureRect) {
    let ppp = ctx.pixels_per_point();
    let fraction = |coord: u16| f32::from(coord) / 65_536.0;
    let hot = egui::pos2(
        picture.x + fraction(sprite.position.0) * picture.width,
        picture.y + fraction(sprite.position.1) * picture.height,
    );
    let min = egui::pos2(
        hot.x - sprite.hot.0 * picture.scale,
        hot.y - sprite.hot.1 * picture.scale,
    );
    let size = egui::vec2(sprite.size.0 * picture.scale, sprite.size.1 * picture.scale);
    let rect = egui::Rect::from_min_size(min, size);
    let rect = egui::Rect::from_min_max(
        (rect.min.to_vec2() / ppp).to_pos2(),
        (rect.max.to_vec2() / ppp).to_pos2(),
    );
    ctx.layer_painter(egui::LayerId::new(
        egui::Order::Tooltip,
        egui::Id::unique("rr-remote-cursor"),
    ))
    .image(
        sprite.texture,
        rect,
        egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
        egui::Color32::WHITE,
    );
}

impl ApplicationHandler<UserEvent> for App<'_> {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.window.is_some() {
            return;
        }
        match self.open(event_loop) {
            Ok(()) => self.show_frame(event_loop),
            Err(err) => self.finish(event_loop, Outcome::Failed(format!("{err:#}"))),
        }
    }

    fn window_event(&mut self, event_loop: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        let Some(window) = self.window.clone() else {
            return;
        };
        if let Some(state) = &mut self.egui_state {
            let response = state.on_window_event(&window, &event);
            if response.repaint && (self.overlay.visible || self.over_toolbar()) {
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
                let (_, action) = self.redraw();
                self.act(event_loop, action);
            }
            WindowEvent::Focused(focused) => self.on_focus(focused),
            WindowEvent::KeyboardInput { event, .. } => self.on_key(&window, &event),
            WindowEvent::CursorMoved { position, .. } => {
                self.on_pointer(event_loop, &window, Some(position));
            }
            WindowEvent::CursorLeft { .. } => self.on_pointer(event_loop, &window, None),
            WindowEvent::MouseInput { state, button, .. } => self.on_button(state, button),
            WindowEvent::MouseWheel { delta, .. } => self.on_wheel(delta),
            _ => {}
        }
    }

    fn user_event(&mut self, event_loop: &ActiveEventLoop, event: UserEvent) {
        match event {
            UserEvent::Frame => self.show_frame(event_loop),
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
            UserEvent::Key(key, down) => {
                if let Some(input) = &mut self.input {
                    input.key(key, down, Instant::now());
                }
            }
            UserEvent::Cursor(msg) => {
                if self.cursor.update(msg) {
                    self.applied_cursor = None;
                }
                if self.input.is_some() {
                    self.update_local_pointer(event_loop);
                } else if let Some(window) = &self.window {
                    window.request_redraw();
                }
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
        let mut wake = self.next_tick;
        if let Some(due) = self.input.as_mut().and_then(|input| input.tick(now)) {
            wake = wake.min(due);
        }
        event_loop.set_control_flow(ControlFlow::WaitUntil(wake));
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
