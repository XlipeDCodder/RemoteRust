//! The Windows tray: an icon in the notification area (`tray-icon`).

use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

use super::{OnAction, TrayAction, icon, status_text};

fn tooltip(viewer: Option<&str>) -> String {
    format!("RustRemote: {}", status_text(viewer))
}

/// Menu item ids; the event handlers map them back to actions.
const OPEN: &str = "open";
const STOP: &str = "stop";
const QUIT: &str = "quit";

pub struct Tray {
    icon: TrayIcon,
    stop: MenuItem,
}

fn tray_icon(sharing: bool) -> anyhow::Result<Icon> {
    Ok(Icon::from_rgba(
        icon::pixels(sharing),
        icon::SIZE,
        icon::SIZE,
    )?)
}

impl Tray {
    /// Adds the icon. Needs the thread's message loop (the event loop's
    /// thread, once it runs).
    pub fn new(_runtime: &tokio::runtime::Handle, on_action: OnAction) -> anyhow::Result<Self> {
        let on_menu = on_action.clone();
        MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            let action = match event.id.as_ref() {
                OPEN => TrayAction::Open,
                STOP => TrayAction::Stop,
                QUIT => TrayAction::Quit,
                _ => return,
            };
            on_menu(action);
        }));
        TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
            if matches!(
                event,
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } | TrayIconEvent::DoubleClick { .. }
            ) {
                on_action(TrayAction::Open);
            }
        }));

        let open = MenuItem::with_id(OPEN, "Open RustRemote", true, None);
        let stop = MenuItem::with_id(STOP, "Stop sharing", false, None);
        let quit = MenuItem::with_id(QUIT, "Quit RustRemote", true, None);
        let menu = Menu::new();
        menu.append_items(&[&open, &stop, &PredefinedMenuItem::separator(), &quit])?;
        let icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip(tooltip(None))
            .with_title("RustRemote")
            .with_icon(tray_icon(false)?)
            .with_menu_on_left_click(false)
            .build()?;
        Ok(Self { icon, stop })
    }

    /// Shows whether, and with whom, the screen is shared.
    pub fn update(&mut self, viewer: Option<&str>) {
        if let Ok(icon) = tray_icon(viewer.is_some()) {
            let _ = self.icon.set_icon(Some(icon));
        }
        let _ = self.icon.set_tooltip(Some(tooltip(viewer)));
        self.stop.set_enabled(viewer.is_some());
    }

    /// The notification area is always there.
    pub fn shown(&self) -> bool {
        true
    }
}
