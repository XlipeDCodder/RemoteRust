//! The tray icon (blueprint v2 §7.5): gray while idle, red while sharing,
//! with a menu to open the window, stop sharing or quit.
//!
//! - Windows: the notification area (`tray-icon`).
//! - Linux: our own StatusNotifierItem over D-Bus (`sni`), shown by KDE
//!   and most desktops; GNOME needs the AppIndicator extension (on by
//!   default on Ubuntu).
//!
//! Without a tray the Agent window stays reachable on the taskbar.

#[cfg(target_os = "linux")]
mod sni;
#[cfg(windows)]
mod win;

#[cfg(target_os = "linux")]
use sni as imp;
#[cfg(windows)]
use win as imp;

use std::sync::Arc;

use super::icon;

/// What the tray asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    /// Show the Agent window (menu item or a click on the icon).
    Open,
    /// Stop sharing (the kill switch).
    Stop,
    /// Quit the Agent.
    Quit,
}

/// Receives tray actions, from any thread.
pub type OnAction = Arc<dyn Fn(TrayAction) + Send + Sync>;

/// What the tooltip says.
fn status_text(viewer: Option<&str>) -> String {
    viewer.map_or_else(
        || "Not sharing".to_owned(),
        |viewer| format!("Sharing this screen with \"{viewer}\""),
    )
}

pub struct Tray {
    inner: imp::Tray,
    /// The Viewer last shown, to update only on changes.
    shown_viewer: Option<Option<String>>,
}

impl Tray {
    /// Adds the tray icon. On Windows call it from the event loop's thread
    /// once the loop runs; on Linux the D-Bus side runs on `runtime`.
    ///
    /// # Errors
    /// No tray on this system.
    pub fn new(runtime: &tokio::runtime::Handle, on_action: OnAction) -> anyhow::Result<Self> {
        Ok(Self {
            inner: imp::Tray::new(runtime, on_action)?,
            shown_viewer: None,
        })
    }

    /// Shows whether, and with whom, the screen is shared.
    pub fn update(&mut self, viewer: Option<&str>) {
        if self.shown_viewer.as_ref().map(Option::as_deref) == Some(viewer) {
            return;
        }
        self.inner.update(viewer);
        self.shown_viewer = Some(viewer.map(str::to_owned));
    }

    /// Whether a tray shows the icon now, so the window may hide to it.
    pub fn shown(&self) -> bool {
        self.inner.shown()
    }
}

/// Other systems: no tray.
#[cfg(not(any(windows, target_os = "linux")))]
mod imp {
    use super::OnAction;

    pub struct Tray;

    impl Tray {
        pub fn new(
            _runtime: &tokio::runtime::Handle,
            _on_action: OnAction,
        ) -> anyhow::Result<Self> {
            anyhow::bail!("no tray on this system")
        }

        pub fn update(&mut self, _viewer: Option<&str>) {}

        pub fn shown(&self) -> bool {
            false
        }
    }
}
