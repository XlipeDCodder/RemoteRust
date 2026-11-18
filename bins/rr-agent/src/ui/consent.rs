//! The consent dialog (blueprint v2 §7.3): who asks, for what, and a
//! countdown to the automatic denial.
//!
//! Against accidental acceptance: Accept only works after the dialog has
//! been up for a moment, Enter does nothing, and Esc or closing the window
//! denies.

use std::time::{Duration, Instant};

use egui::{Color32, RichText};
use rr_proto::Permissions;

use crate::hub::Pending;

/// How long the dialog is up before Accept works.
const ARM_DELAY: Duration = Duration::from_secs(1);

/// The dialog's size, in logical pixels.
pub const SIZE: (f64, f64) = (470.0, 270.0);

/// The local user's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    Accept(Permissions),
    Deny,
}

pub struct Dialog {
    /// Identifies the request (see [`Pending::since`]).
    pub since: Instant,
    shown: Instant,
    viewer: String,
    fingerprint: String,
    requested: Permissions,
    allow_control: bool,
    deadline: Instant,
}

impl Dialog {
    pub fn new(pending: &Pending) -> Self {
        Self {
            since: pending.since,
            shown: Instant::now(),
            viewer: pending.viewer.clone(),
            fingerprint: pending.fingerprint.clone(),
            requested: pending.permissions,
            allow_control: pending.permissions.contains(Permissions::CONTROL),
            deadline: pending.deadline,
        }
    }

    /// The dialog's contents; `Some` once the user answered.
    pub fn ui(&mut self, ui: &mut egui::Ui) -> Option<Choice> {
        let armed = self.shown.elapsed() >= ARM_DELAY;
        let remaining = self
            .deadline
            .saturating_duration_since(Instant::now())
            .as_secs();
        let wants_control = self.requested.contains(Permissions::CONTROL);
        let mut choice = None;
        if ui.input(|input| input.key_pressed(egui::Key::Escape)) {
            choice = Some(Choice::Deny);
        }
        egui::CentralPanel::default().show(ui, |ui| {
            ui.add_space(6.0);
            let what = if wants_control {
                "see and control this screen"
            } else {
                "see this screen"
            };
            ui.label(RichText::new(format!("\"{}\" wants to {what}.", self.viewer)).heading());
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label("Device fingerprint:");
                ui.label(RichText::new(&self.fingerprint).monospace());
            });
            ui.label(
                RichText::new("Accept only if you expect this and know the device.")
                    .color(ui.visuals().weak_text_color()),
            );
            ui.add_space(8.0);
            if wants_control {
                ui.checkbox(
                    &mut self.allow_control,
                    "Allow control of this computer's mouse and keyboard",
                );
            } else {
                ui.label("The device will only see the screen.");
            }
            ui.add_space(8.0);
            ui.label(format!("Denied automatically in {remaining} s."));
            ui.add_space(10.0);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Min), |ui| {
                let accept =
                    egui::Button::new(RichText::new("  Accept  ").color(Color32::WHITE).strong())
                        .fill(Color32::from_rgb(0x2E, 0x7D, 0x32));
                if ui.add_enabled(armed, accept).clicked() {
                    choice = crate::consent::grant(self.requested, self.allow_control)
                        .map_or(Some(Choice::Deny), |granted| Some(Choice::Accept(granted)));
                }
                if ui.button("  Deny  ").clicked() {
                    choice = Some(Choice::Deny);
                }
            });
        });
        choice
    }

    /// When the dialog should be drawn again (countdown, arming).
    pub fn refresh(&self) -> Duration {
        if self.shown.elapsed() < ARM_DELAY {
            Duration::from_millis(100)
        } else {
            Duration::from_millis(250)
        }
    }
}
