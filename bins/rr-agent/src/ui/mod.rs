//! The Agent's window, consent dialog and tray icon (blueprint v2 §7.3,
//! §7.5, §7.6), drawn with egui on wgpu on the main thread. The network
//! side runs on the async runtime and talks to this through the
//! [`Hub`], which wakes the event loop when something changes.
//!
//! The session border is not drawn here: the capture thread shows it with
//! the platform's own windows (see `rr_platform::border`), so it also
//! works in console mode.

mod consent;
mod gpu;
mod icon;
mod tray;
mod window;

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use tray_icon::menu::{MenuEvent, MenuId};
use tray_icon::{MouseButton, MouseButtonState, TrayIconEvent};
use winit::application::ApplicationHandler;
use winit::dpi::{LogicalSize, PhysicalPosition};
use winit::event::WindowEvent;
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop, EventLoopProxy};
use winit::window::{UserAttentionType, Window, WindowButtons, WindowId, WindowLevel};

use self::consent::{Choice, Dialog};
use self::gpu::{Graphics, Painter};
use self::tray::{Tray, TrayAction};
use self::window::Action;
use crate::hub::{Hub, Via};

/// How often the main window redraws while visible (clocks, countdowns).
const TICK: Duration = Duration::from_secs(1);

/// Wakes the event loop.
#[derive(Debug)]
pub enum UiEvent {
    /// The hub changed.
    Wake,
    /// A tray menu item was clicked.
    Menu(MenuId),
    /// The tray icon was clicked.
    TrayClicked,
}

/// Connects to the window system; fails without a graphical session.
pub fn event_loop() -> anyhow::Result<EventLoop<UiEvent>> {
    EventLoop::<UiEvent>::with_user_event()
        .build()
        .context("cannot connect to the window system")
}

/// Sends `event` through `proxy`; the loop may be gone already.
fn send(proxy: &Mutex<EventLoopProxy<UiEvent>>, event: UiEvent) {
    let _ = proxy
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .send_event(event);
}

/// Shows the window and tray icon until the user quits (or Ctrl+C).
///
/// # Errors
/// The window could not be opened (no usable graphics, for example).
pub fn run(event_loop: EventLoop<UiEvent>, hub: Arc<Hub>) -> anyhow::Result<()> {
    let proxy = event_loop.create_proxy();
    let wake = Mutex::new(proxy.clone());
    hub.set_waker(move || send(&wake, UiEvent::Wake));
    let menu = Mutex::new(proxy.clone());
    MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
        send(&menu, UiEvent::Menu(event.id));
    }));
    let clicks = Mutex::new(proxy);
    TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
        if matches!(
            event,
            TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } | TrayIconEvent::DoubleClick { .. }
        ) {
            send(&clicks, UiEvent::TrayClicked);
        }
    }));

    let mut app = App {
        hub,
        graphics: None,
        main: None,
        hidden: false,
        consent: None,
        tray: None,
        next_tick: Instant::now(),
        failure: None,
    };
    event_loop
        .run_app(&mut app)
        .context("the window system failed")?;
    match app.failure.take() {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

struct App {
    hub: Arc<Hub>,
    graphics: Option<Graphics>,
    main: Option<Painter>,
    /// The main window is hidden (or minimized) by its close button.
    hidden: bool,
    consent: Option<(Painter, Dialog)>,
    tray: Option<Tray>,
    next_tick: Instant,
    failure: Option<anyhow::Error>,
}

impl App {
    fn open_main(&mut self, event_loop: &ActiveEventLoop) -> anyhow::Result<()> {
        let attributes = Window::default_attributes()
            .with_title("RustRemote Agent")
            .with_inner_size(LogicalSize::new(window::SIZE.0, window::SIZE.1))
            .with_min_inner_size(LogicalSize::new(360.0, 420.0))
            .with_window_icon(icon::window_icon(false));
        let window = Arc::new(
            event_loop
                .create_window(attributes)
                .context("cannot open the Agent window")?,
        );
        let graphics = self
            .graphics
            .get_or_insert_with(|| Graphics::new(event_loop));
        self.main = Some(graphics.painter(window)?);
        Ok(())
    }

    fn open_consent(&mut self, event_loop: &ActiveEventLoop, dialog: Dialog) -> anyhow::Result<()> {
        let mut attributes = Window::default_attributes()
            .with_title("RustRemote: screen request")
            .with_inner_size(LogicalSize::new(consent::SIZE.0, consent::SIZE.1))
            .with_resizable(false)
            .with_enabled_buttons(WindowButtons::CLOSE)
            .with_window_level(WindowLevel::AlwaysOnTop)
            .with_window_icon(icon::window_icon(false))
            .with_active(true);
        // Centered on the primary monitor.
        if let Some(monitor) = event_loop
            .primary_monitor()
            .or_else(|| event_loop.available_monitors().next())
        {
            let scale = monitor.scale_factor();
            let size = LogicalSize::new(consent::SIZE.0, consent::SIZE.1).to_physical::<i32>(scale);
            let area = monitor.size();
            let origin = monitor.position();
            let offset = |total: u32, used: i32| {
                i32::try_from(total)
                    .unwrap_or(i32::MAX)
                    .saturating_sub(used)
                    .max(0)
                    / 2
            };
            attributes = attributes.with_position(PhysicalPosition::new(
                origin.x.saturating_add(offset(area.width, size.width)),
                origin.y.saturating_add(offset(area.height, size.height)),
            ));
        }
        let window = Arc::new(
            event_loop
                .create_window(attributes)
                .context("cannot open the consent dialog")?,
        );
        window.focus_window();
        window.request_user_attention(Some(UserAttentionType::Critical));
        let graphics = self
            .graphics
            .get_or_insert_with(|| Graphics::new(event_loop));
        let painter = graphics.painter(window)?;
        self.consent = Some((painter, dialog));
        Ok(())
    }

    /// Brings the windows and the tray in line with the hub.
    fn sync(&mut self, event_loop: &ActiveEventLoop) {
        if self.hub.quit_requested() {
            event_loop.exit();
            return;
        }
        self.hub.forget_withdrawn();
        let (dialog, viewer) = {
            let state = self.hub.state();
            (
                state.pending.as_ref().map(Dialog::new),
                state.live.as_ref().map(|live| live.viewer.clone()),
            )
        };
        let shown = self.consent.as_ref().map(|(_, shown)| shown.since);
        match dialog {
            Some(dialog) if shown == Some(dialog.since) => {}
            Some(dialog) => {
                self.consent = None;
                if let Err(err) = self.open_consent(event_loop, dialog) {
                    tracing::error!(error = format!("{err:#}"), "cannot show the consent dialog");
                    self.hub.answer(None);
                }
            }
            None => self.consent = None,
        }
        if let Some(tray) = &mut self.tray {
            tray.update(viewer.as_deref());
        }
        if let Some(main) = &self.main {
            main.window()
                .set_window_icon(icon::window_icon(viewer.is_some()));
            main.window().request_redraw();
        }
    }

    fn show_main(&mut self) {
        if let Some(main) = &self.main {
            let window = main.window();
            window.set_visible(true);
            window.set_minimized(false);
            window.focus_window();
            window.request_redraw();
            self.hidden = false;
        }
    }

    /// The close button hides the window to the tray (Windows) or
    /// minimizes it: quitting is in the window and the tray menu.
    fn hide_main(&mut self) {
        if let Some(main) = &self.main {
            if cfg!(windows) && self.tray.is_some() {
                main.window().set_visible(false);
            } else {
                main.window().set_minimized(true);
            }
            self.hidden = true;
        }
    }

    fn main_event(&mut self, event_loop: &ActiveEventLoop, event: &WindowEvent) {
        let Some(main) = &mut self.main else {
            return;
        };
        main.on_event(event);
        match event {
            WindowEvent::CloseRequested => self.hide_main(),
            WindowEvent::RedrawRequested => {
                let hub = Arc::clone(&self.hub);
                let mut action = None;
                main.paint(|ui| {
                    if let Some(clicked) = window::ui(ui, &hub) {
                        action = Some(clicked);
                    }
                });
                match action {
                    Some(Action::StopSharing) => self.hub.kill(Via::Window),
                    Some(Action::Quit) => event_loop.exit(),
                    None => {}
                }
            }
            _ => {}
        }
    }

    fn consent_event(&mut self, event: &WindowEvent) {
        let Some((painter, dialog)) = &mut self.consent else {
            return;
        };
        painter.on_event(event);
        let choice = match event {
            WindowEvent::CloseRequested => Some(Choice::Deny),
            WindowEvent::RedrawRequested => {
                let mut choice = None;
                painter.paint(|ui| {
                    if let Some(answer) = dialog.ui(ui) {
                        choice = Some(answer);
                    }
                });
                choice
            }
            _ => None,
        };
        match choice {
            Some(Choice::Accept(permissions)) => {
                self.consent = None;
                self.hub.answer(Some(permissions));
            }
            Some(Choice::Deny) => {
                self.consent = None;
                self.hub.answer(None);
            }
            None => {}
        }
    }
}

impl ApplicationHandler<UiEvent> for App {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.main.is_some() {
            return;
        }
        if let Err(err) = self.open_main(event_loop) {
            self.failure = Some(err);
            event_loop.exit();
            return;
        }
        // On Windows the tray icon needs this thread's message loop, which
        // is running now.
        match Tray::new() {
            Ok(tray) => self.tray = Some(tray),
            Err(err) => {
                tracing::warn!(error = format!("{err:#}"), "no tray icon");
            }
        }
        self.sync(event_loop);
    }

    fn user_event(&mut self, event_loop: &ActiveEventLoop, event: UiEvent) {
        match event {
            UiEvent::Wake => self.sync(event_loop),
            UiEvent::Menu(id) => match self.tray.as_ref().and_then(|tray| tray.action(&id)) {
                Some(TrayAction::Open) => self.show_main(),
                Some(TrayAction::Stop) => self.hub.kill(Via::Tray),
                Some(TrayAction::Quit) => event_loop.exit(),
                None => {}
            },
            UiEvent::TrayClicked => self.show_main(),
        }
    }

    fn window_event(&mut self, event_loop: &ActiveEventLoop, id: WindowId, event: WindowEvent) {
        if self.main.as_ref().is_some_and(|main| main.id() == id) {
            self.main_event(event_loop, &event);
        } else if self
            .consent
            .as_ref()
            .is_some_and(|(painter, _)| painter.id() == id)
        {
            self.consent_event(&event);
        }
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        // A request the Viewer withdrew (or that timed out) closes the
        // dialog.
        if self.consent.is_some() && self.hub.forget_withdrawn() {
            self.consent = None;
        }
        let now = Instant::now();
        let mut wake = None::<Instant>;
        let mut at = |when: Instant| {
            wake = Some(wake.map_or(when, |wake| wake.min(when)));
        };
        // Clocks and countdowns: the main window every second, the dialog
        // more often.
        let main_shown = self.main.is_some() && !self.hidden;
        if main_shown || self.consent.is_some() {
            if now >= self.next_tick {
                let period = self
                    .consent
                    .as_ref()
                    .map_or(TICK, |(_, dialog)| dialog.refresh());
                self.next_tick = now.checked_add(period).unwrap_or(now);
                if let Some(main) = self.main.as_ref().filter(|_| main_shown) {
                    main.window().request_redraw();
                }
                if let Some((painter, _)) = &self.consent {
                    painter.window().request_redraw();
                }
            }
            at(self.next_tick);
        }
        for painter in self
            .main
            .iter_mut()
            .chain(self.consent.iter_mut().map(|(painter, _)| painter))
        {
            if let Some(when) = painter.repaint_at {
                if when <= now {
                    painter.repaint_at = None;
                    painter.window().request_redraw();
                } else {
                    at(when);
                }
            }
        }
        event_loop.set_control_flow(wake.map_or(ControlFlow::Wait, ControlFlow::WaitUntil));
    }
}
