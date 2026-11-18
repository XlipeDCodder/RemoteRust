//! The Agent window: this device, the session code, the session being
//! shared with its Stop button, the kill-switch hint and recent failed
//! attempts.
//!
//! While a session runs the Viewer may be the one clicking here, so the
//! window then offers only what reduces access (stop sharing, quit), and
//! the session code is hidden.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use egui::{Color32, RichText};
use rr_net::FailureKind;
use rr_proto::Permissions;

use crate::hub::Hub;

/// The window's size, in logical pixels.
pub const SIZE: (f64, f64) = (460.0, 600.0);

/// Failed attempts listed.
const LISTED_FAILURES: usize = 8;

const RED: Color32 = Color32::from_rgb(0xE5, 0x39, 0x35);

/// What the user asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    StopSharing,
    Quit,
}

/// What the window shows, copied out of the hub so its lock is not held
/// while drawing.
struct Snapshot {
    code: Option<(String, Duration)>,
    live: Option<Live>,
    pending: Option<String>,
    failures: Vec<(Duration, IpAddr, FailureKind, Duration)>,
    failures_total: u64,
    pairing_paused: Option<Duration>,
    listening: Vec<String>,
}

struct Live {
    viewer: String,
    fingerprint: String,
    permissions: Permissions,
    elapsed: Duration,
    secure: bool,
}

impl Snapshot {
    fn of(hub: &Hub) -> Self {
        let now = Instant::now();
        let state = hub.state();
        Self {
            code: state.code.as_ref().map(|(code, drawn)| {
                let left = hub
                    .code_ttl
                    .saturating_sub(now.saturating_duration_since(*drawn));
                (code.clone(), left)
            }),
            live: state.live.as_ref().map(|live| Live {
                viewer: live.viewer.clone(),
                fingerprint: live.fingerprint.clone(),
                permissions: live.permissions,
                elapsed: now.saturating_duration_since(live.started),
                secure: live.secure,
            }),
            pending: state.pending.as_ref().map(|pending| pending.viewer.clone()),
            failures: state
                .failures
                .iter()
                .rev()
                .take(LISTED_FAILURES)
                .map(|failure| {
                    (
                        now.saturating_duration_since(failure.at),
                        failure.source,
                        failure.kind,
                        failure.blocked_for,
                    )
                })
                .collect(),
            failures_total: state.failures_total,
            pairing_paused: state
                .pairing_suspended_until
                .map(|until| until.saturating_duration_since(now))
                .filter(|left| !left.is_zero()),
            listening: state.listening.clone(),
        }
    }
}

/// `m:ss`, or `h:mm:ss` past an hour.
fn clock(duration: Duration) -> String {
    let secs = duration.as_secs();
    let (hours, minutes, seconds) = (secs / 3600, secs / 60 % 60, secs % 60);
    if hours > 0 {
        format!("{hours}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes}:{seconds:02}")
    }
}

/// "12 s ago", "3 min ago", "2 h ago".
fn ago(duration: Duration) -> String {
    let secs = duration.as_secs();
    if secs < 60 {
        format!("{secs} s ago")
    } else if secs < 3600 {
        format!("{} min ago", secs / 60)
    } else {
        format!("{} h ago", secs / 3600)
    }
}

fn describe(kind: FailureKind) -> &'static str {
    match kind {
        FailureKind::Handshake => "unknown device or bad handshake",
        FailureKind::Timeout => "too slow to authenticate",
        FailureKind::NotPaired => "not paired",
        FailureKind::PairingUnavailable => "pairing unavailable",
        FailureKind::WrongCode => "wrong session code",
        FailureKind::Protocol => "protocol error",
    }
}

/// Draws the window; returns what the user clicked.
pub fn ui(ui: &mut egui::Ui, hub: &Hub) -> Option<Action> {
    let snapshot = Snapshot::of(hub);
    let mut action = None;
    egui::CentralPanel::default().show(ui, |ui| {
        egui::ScrollArea::vertical().show(ui, |ui| {
            header(ui, hub);
            ui.separator();
            if session(ui, &snapshot, hub) {
                action = Some(Action::StopSharing);
            }
            ui.separator();
            details(ui, &snapshot, hub);
            ui.add_space(12.0);
            if ui.button("Quit RustRemote").clicked() {
                action = Some(Action::Quit);
            }
        });
    });
    action
}

fn header(ui: &mut egui::Ui, hub: &Hub) {
    ui.add_space(4.0);
    ui.label(RichText::new("RustRemote Agent").heading().strong());
    ui.horizontal(|ui| {
        ui.label("This device:");
        ui.label(RichText::new(&hub.device_name).strong());
    });
    ui.horizontal(|ui| {
        ui.label("Fingerprint:");
        ui.label(RichText::new(&hub.fingerprint).monospace());
    });
}

/// The session, the request or the code; `true` if Stop was clicked.
fn session(ui: &mut egui::Ui, snapshot: &Snapshot, hub: &Hub) -> bool {
    ui.add_space(4.0);
    if let Some(live) = &snapshot.live {
        let what = if live.permissions.contains(Permissions::CONTROL) {
            "view and control"
        } else {
            "view only"
        };
        ui.label(
            RichText::new(format!("● Sharing this screen with \"{}\"", live.viewer))
                .color(RED)
                .strong()
                .size(17.0),
        );
        ui.label(format!("{what}, for {}", clock(live.elapsed)));
        ui.label(
            RichText::new(format!("Device fingerprint: {}", live.fingerprint))
                .monospace()
                .color(ui.visuals().weak_text_color()),
        );
        if live.secure {
            ui.label(
                "A system prompt is showing: the viewer sees nothing and cannot control \
                 until it is answered here.",
            );
        }
        ui.add_space(6.0);
        let stop = egui::Button::new(
            RichText::new("  Stop sharing  ")
                .color(Color32::WHITE)
                .strong()
                .size(16.0),
        )
        .fill(RED);
        let clicked = ui.add(stop).clicked();
        if let Some(hotkey) = hub.hotkey() {
            ui.label(format!("or press {hotkey}, anytime."));
        }
        return clicked;
    }
    if let Some(viewer) = &snapshot.pending {
        ui.label(RichText::new(format!("\"{viewer}\" is asking to connect…")).strong());
        return false;
    }
    ui.label(RichText::new("○ Not sharing").strong().size(17.0));
    match &snapshot.code {
        Some((code, left)) => {
            ui.add_space(6.0);
            ui.label("Session code, to pair a new Viewer:");
            let (head, tail) = code.split_at_checked(3).unwrap_or((code, ""));
            ui.label(
                RichText::new(format!("{head} {tail}"))
                    .monospace()
                    .strong()
                    .size(34.0),
            );
            ui.label(
                RichText::new(format!("single use, renewed in {}", clock(*left)))
                    .color(ui.visuals().weak_text_color()),
            );
        }
        None => {
            ui.label("Pairing is off: only paired Viewers can connect.");
        }
    }
    if let Some(left) = snapshot.pairing_paused {
        ui.add_space(4.0);
        ui.colored_label(
            RED,
            format!(
                "Pairing new devices is paused for {} after repeated failed attempts.",
                clock(left)
            ),
        );
    }
    false
}

fn details(ui: &mut egui::Ui, snapshot: &Snapshot, hub: &Hub) {
    match hub.hotkey() {
        Some(hotkey) => {
            ui.label(format!("Kill switch: {hotkey} ends every session at once."));
        }
        None => {
            ui.label("Kill switch: Stop sharing here or in the tray icon ends a session.");
        }
    }
    ui.add_space(6.0);
    ui.label("Listening on:");
    if snapshot.listening.is_empty() {
        ui.label(
            RichText::new("  nothing (no interface matches the configuration)")
                .color(ui.visuals().weak_text_color()),
        );
    }
    for address in &snapshot.listening {
        ui.label(RichText::new(format!("  {address}")).monospace());
    }
    ui.add_space(6.0);
    let title = format!("Failed attempts: {}", snapshot.failures_total);
    egui::CollapsingHeader::new(title)
        .id_salt("failures")
        .default_open(false)
        .show(ui, |ui| {
            if snapshot.failures.is_empty() {
                ui.label("None since the Agent started.");
            }
            for (ago_by, source, kind, blocked) in &snapshot.failures {
                let blocked = if blocked.is_zero() {
                    String::new()
                } else {
                    format!(", blocked {} s", blocked.as_secs())
                };
                ui.label(format!(
                    "{}  {source}: {}{blocked}",
                    ago(*ago_by),
                    describe(*kind)
                ));
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_naturally() {
        assert_eq!(clock(Duration::from_secs(65)), "1:05");
        assert_eq!(clock(Duration::from_secs(3_725)), "1:02:05");
        assert_eq!(ago(Duration::from_secs(5)), "5 s ago");
        assert_eq!(ago(Duration::from_secs(185)), "3 min ago");
        assert_eq!(ago(Duration::from_secs(7_300)), "2 h ago");
    }
}
