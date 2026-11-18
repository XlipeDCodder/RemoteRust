//! The tray icon (blueprint v2 §7.5): gray while idle, red while sharing,
//! with a menu to open the window, stop sharing or quit.
//!
//! Windows uses the notification area; Linux uses StatusNotifierItem over
//! D-Bus (KDE, most desktops; GNOME needs the AppIndicator extension).
//! Without a tray the Agent window stays reachable on the taskbar.

use tray_icon::menu::{Menu, MenuId, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

use super::icon;

/// What a menu item asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    Open,
    Stop,
    Quit,
}

pub struct Tray {
    icon: TrayIcon,
    open: MenuItem,
    stop: MenuItem,
    quit: MenuItem,
    /// The Viewer shown, to update only on changes.
    shown: Option<Option<String>>,
}

fn tray_icon(sharing: bool) -> anyhow::Result<Icon> {
    Ok(Icon::from_rgba(
        icon::pixels(sharing),
        icon::SIZE,
        icon::SIZE,
    )?)
}

impl Tray {
    pub fn new() -> anyhow::Result<Self> {
        let open = MenuItem::new("Open RustRemote", true, None);
        let stop = MenuItem::new("Stop sharing", false, None);
        let quit = MenuItem::new("Quit RustRemote", true, None);
        let menu = Menu::new();
        menu.append_items(&[&open, &stop, &PredefinedMenuItem::separator(), &quit])?;
        let icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("RustRemote: not sharing")
            .with_title("RustRemote")
            .with_icon(tray_icon(false)?)
            .with_menu_on_left_click(false)
            .build()?;
        Ok(Self {
            icon,
            open,
            stop,
            quit,
            shown: None,
        })
    }

    /// Shows whether, and with whom, the screen is shared.
    pub fn update(&mut self, viewer: Option<&str>) {
        let viewer = viewer.map(str::to_owned);
        if self.shown.as_ref() == Some(&viewer) {
            return;
        }
        let tooltip = viewer.as_ref().map_or_else(
            || "RustRemote: not sharing".to_owned(),
            |viewer| format!("RustRemote: sharing this screen with \"{viewer}\""),
        );
        if let Ok(icon) = tray_icon(viewer.is_some()) {
            let _ = self.icon.set_icon(Some(icon));
        }
        let _ = self.icon.set_tooltip(Some(tooltip));
        self.stop.set_enabled(viewer.is_some());
        self.shown = Some(viewer);
    }

    /// The action of a clicked menu item.
    pub fn action(&self, id: &MenuId) -> Option<TrayAction> {
        if id == self.open.id() {
            Some(TrayAction::Open)
        } else if id == self.stop.id() {
            Some(TrayAction::Stop)
        } else if id == self.quit.id() {
            Some(TrayAction::Quit)
        } else {
            None
        }
    }
}
