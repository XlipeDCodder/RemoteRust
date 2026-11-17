//! The Viewer's own functions while every key goes to the remote: a small
//! tab at the top center of the window that opens, under the pointer, into
//! a bar with Statistics, Full screen and Disconnect.
//!
//! Over the tab or the open bar, the mouse belongs to the Viewer and
//! nothing is sent to the Agent.

/// The closed tab, in points.
const TAB: egui::Vec2 = egui::vec2(72.0, 6.0);
/// How far below the tab the pointer may be and still open it.
const TAB_REACH: f32 = 4.0;
/// Margin around the open bar before it closes.
const BAR_SLACK: f32 = 8.0;

/// What the user picked in the bar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    ToggleStats,
    ToggleFullscreen,
    Disconnect,
}

/// The state of the bar.
#[derive(Debug, Default)]
pub struct Toolbar {
    open: bool,
    /// Where the open bar was drawn last, in points.
    bar: Option<egui::Rect>,
}

impl Toolbar {
    /// The closed tab for a window `width` points wide.
    fn tab(width: f32) -> egui::Rect {
        egui::Rect::from_min_size(egui::pos2((width - TAB.x) / 2.0, 0.0), TAB)
    }

    /// Follows the pointer (in points; `None` when it left the window).
    /// Returns whether the bar opened or closed.
    pub fn pointer_moved(&mut self, pointer: Option<egui::Pos2>, width: f32) -> bool {
        let was_open = self.open;
        self.open = pointer.is_some_and(|pointer| {
            if self.open {
                // Before the first drawing, the tab's column stands in for
                // the bar.
                let bar = self
                    .bar
                    .unwrap_or_else(|| Self::tab(width).expand2(egui::vec2(120.0, 30.0)));
                bar.expand(BAR_SLACK).contains(pointer)
            } else {
                Self::tab(width)
                    .expand2(egui::vec2(0.0, TAB_REACH))
                    .contains(pointer)
            }
        });
        if !self.open {
            self.bar = None;
        }
        was_open != self.open
    }

    /// Whether the pointer is over the tab or the open bar, so mouse input
    /// is the Viewer's.
    pub fn contains(&self, pointer: egui::Pos2, width: f32) -> bool {
        if self.open {
            self.bar
                .is_none_or(|bar| bar.expand(BAR_SLACK).contains(pointer))
        } else {
            Self::tab(width)
                .expand2(egui::vec2(0.0, TAB_REACH))
                .contains(pointer)
        }
    }

    /// Draws the tab or the bar and returns what was clicked.
    pub fn ui(
        &mut self,
        ctx: &egui::Context,
        mode: &str,
        stats: bool,
        fullscreen: bool,
    ) -> Option<Action> {
        let width = ctx.content_rect().width();
        if !self.open {
            egui::Area::new(egui::Id::unique("rr-toolbar-tab"))
                .order(egui::Order::Foreground)
                .fixed_pos(Self::tab(width).min)
                .interactable(false)
                .show(ctx, |ui| {
                    let (rect, _) = ui.allocate_exact_size(TAB, egui::Sense::hover());
                    ui.painter().rect_filled(
                        rect,
                        egui::CornerRadius {
                            nw: 0,
                            ne: 0,
                            sw: 3,
                            se: 3,
                        },
                        egui::Color32::from_white_alpha(110),
                    );
                });
            return None;
        }
        let mut action = None;
        let shown = egui::Area::new(egui::Id::unique("rr-toolbar"))
            .order(egui::Order::Foreground)
            .anchor(egui::Align2::CENTER_TOP, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                egui::Frame::new()
                    .fill(egui::Color32::from_black_alpha(225))
                    .inner_margin(egui::Margin::symmetric(10, 6))
                    .corner_radius(egui::CornerRadius {
                        nw: 0,
                        ne: 0,
                        sw: 6,
                        se: 6,
                    })
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(mode).color(egui::Color32::LIGHT_GRAY));
                            ui.separator();
                            if ui.selectable_label(stats, "Statistics").clicked() {
                                action = Some(Action::ToggleStats);
                            }
                            if ui.selectable_label(fullscreen, "Full screen").clicked() {
                                action = Some(Action::ToggleFullscreen);
                            }
                            ui.separator();
                            if ui.button("Disconnect").clicked() {
                                action = Some(Action::Disconnect);
                            }
                        });
                    });
            });
        self.bar = Some(shown.response.rect);
        action
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIDTH: f32 = 1000.0;

    #[test]
    fn the_tab_opens_the_bar_and_leaving_it_closes() {
        let mut toolbar = Toolbar::default();
        assert!(!toolbar.contains(egui::pos2(500.0, 300.0), WIDTH));
        // Near the top, away from the tab: nothing.
        assert!(!toolbar.pointer_moved(Some(egui::pos2(100.0, 1.0)), WIDTH));
        // Over the tab: opens.
        assert!(toolbar.pointer_moved(Some(egui::pos2(500.0, 2.0)), WIDTH));
        assert!(toolbar.contains(egui::pos2(500.0, 2.0), WIDTH));
        // The drawn bar keeps it open while the pointer is on it.
        toolbar.bar = Some(egui::Rect::from_min_max(
            egui::pos2(350.0, 0.0),
            egui::pos2(650.0, 32.0),
        ));
        assert!(!toolbar.pointer_moved(Some(egui::pos2(640.0, 30.0)), WIDTH));
        assert!(toolbar.contains(egui::pos2(640.0, 30.0), WIDTH));
        // Leaving it closes it; leaving the window too.
        assert!(toolbar.pointer_moved(Some(egui::pos2(500.0, 200.0)), WIDTH));
        assert!(!toolbar.contains(egui::pos2(640.0, 30.0), WIDTH));
        toolbar.pointer_moved(Some(egui::pos2(500.0, 2.0)), WIDTH);
        assert!(toolbar.pointer_moved(None, WIDTH));
    }
}
