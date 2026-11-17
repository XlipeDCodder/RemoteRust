//! Statistics overlay, toggled from the toolbar or, viewing only, with F1
//! (blueprint v2 §8.10).
//!
//! Rates and stage times cover the last second. The latency line adds the
//! stage times and half the round trip: the two clocks are never compared.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use rr_media::OpenH264Decoder;
use rr_net::PathStats;

use crate::video::{Counters, Decoded};

/// Stage times summed over the current second.
#[derive(Debug, Default, Clone, Copy)]
struct Stages {
    capture: Duration,
    convert: Duration,
    encode: Duration,
    queue: Duration,
    decode: Duration,
    render: Duration,
}

impl Stages {
    fn add(&mut self, other: &Self) {
        self.capture = self.capture.saturating_add(other.capture);
        self.convert = self.convert.saturating_add(other.convert);
        self.encode = self.encode.saturating_add(other.encode);
        self.queue = self.queue.saturating_add(other.queue);
        self.decode = self.decode.saturating_add(other.decode);
        self.render = self.render.saturating_add(other.render);
    }

    fn average(&self, count: u32) -> Self {
        let avg = |total: Duration| total.checked_div(count).unwrap_or_default();
        Self {
            capture: avg(self.capture),
            convert: avg(self.convert),
            encode: avg(self.encode),
            queue: avg(self.queue),
            decode: avg(self.decode),
            render: avg(self.render),
        }
    }

    fn total(&self) -> Duration {
        [
            self.capture,
            self.convert,
            self.encode,
            self.queue,
            self.decode,
            self.render,
        ]
        .into_iter()
        .fold(Duration::ZERO, Duration::saturating_add)
    }
}

/// Counter values at the previous tick.
#[derive(Debug, Default, Clone, Copy)]
struct Totals {
    bytes: u64,
    frames: u64,
    folded: u64,
    discarded: u64,
    replaced: u64,
}

/// What the last completed second looked like.
#[derive(Debug, Default, Clone, Copy)]
struct Snapshot {
    shown_fps: f64,
    received_fps: f64,
    mbit_per_s: f64,
    stages: Stages,
    folded: u64,
    replaced: u64,
    discarded: u64,
    errors: u64,
    rtt: Duration,
}

pub struct Overlay {
    pub visible: bool,
    agent: String,
    path: String,
    display: String,
    encoder: String,
    picture: Option<(&'static str, u16, u16)>,
    keys: &'static str,
    // Current second.
    shown: u32,
    sums: Stages,
    last_tick: Instant,
    totals: Totals,
    snapshot: Snapshot,
}

impl Overlay {
    pub fn new(agent: &str, path: String, control: bool) -> Self {
        Self {
            visible: false,
            agent: agent.to_owned(),
            path,
            display: String::from("?"),
            encoder: String::from("?"),
            picture: None,
            keys: if control {
                "all keys go to the remote; toolbar at the top center"
            } else {
                "F1 overlay  F11 full screen  (toolbar at the top center)"
            },
            shown: 0,
            sums: Stages::default(),
            last_tick: Instant::now(),
            totals: Totals::default(),
            snapshot: Snapshot::default(),
        }
    }

    pub fn set_display(&mut self, description: &str) {
        description.clone_into(&mut self.display);
    }

    pub fn set_encoder(&mut self, name: String) {
        self.encoder = name;
    }

    /// Records a frame that has just been presented.
    pub fn on_frame(&mut self, frame: &Decoded, render: Duration) {
        let header = &frame.header;
        self.picture = Some((header.codec.as_str(), header.width, header.height));
        let micros = |us: u32| Duration::from_micros(u64::from(us));
        self.sums.add(&Stages {
            capture: micros(header.timings.capture_us),
            convert: micros(header.timings.convert_us),
            encode: micros(header.timings.encode_us),
            queue: frame.queued,
            decode: frame.decode,
            render,
        });
        self.shown = self.shown.saturating_add(1);
    }

    /// Closes the current second.
    pub fn tick(&mut self, counters: &Counters, replaced: u64, path: PathStats) {
        let now = Instant::now();
        let seconds = now
            .saturating_duration_since(self.last_tick)
            .as_secs_f64()
            .max(0.001);
        let totals = Totals {
            bytes: counters.bytes.load(Ordering::Relaxed),
            frames: counters.frames.load(Ordering::Relaxed),
            folded: counters.folded.load(Ordering::Relaxed),
            discarded: counters.discarded.load(Ordering::Relaxed),
            replaced,
        };
        let delta = |now: u64, before: u64| now.saturating_sub(before);
        #[allow(clippy::cast_precision_loss)] // counts per second are small
        let rate = |count: u64| count as f64 / seconds;
        self.snapshot = Snapshot {
            shown_fps: f64::from(self.shown) / seconds,
            received_fps: rate(delta(totals.frames, self.totals.frames)),
            mbit_per_s: rate(delta(totals.bytes, self.totals.bytes)) * 8.0 / 1_000_000.0,
            stages: self.sums.average(self.shown),
            folded: delta(totals.folded, self.totals.folded),
            replaced: delta(totals.replaced, self.totals.replaced),
            discarded: delta(totals.discarded, self.totals.discarded),
            errors: counters.errors.load(Ordering::Relaxed),
            rtt: path.rtt,
        };
        self.totals = totals;
        self.shown = 0;
        self.sums = Stages::default();
        self.last_tick = now;

        let snap = &self.snapshot;
        let ms = |duration: Duration| duration.as_secs_f64() * 1000.0;
        tracing::debug!(
            "video: {:.1} fps shown, {:.1} received, {:.2} Mbit/s, rtt {:.1} ms | agent \
             capture {:.1} convert {:.1} encode {:.1} | viewer queue {:.1} decode {:.1} \
             render {:.1} ms | folded {} replaced {} discarded {} errors {}",
            snap.shown_fps,
            snap.received_fps,
            snap.mbit_per_s,
            ms(snap.rtt),
            ms(snap.stages.capture),
            ms(snap.stages.convert),
            ms(snap.stages.encode),
            ms(snap.stages.queue),
            ms(snap.stages.decode),
            ms(snap.stages.render),
            snap.folded,
            snap.replaced,
            snap.discarded,
            snap.errors,
        );
    }

    /// The overlay text, as label and value pairs.
    fn rows(&self) -> Vec<(&'static str, String)> {
        let snap = &self.snapshot;
        let ms = |duration: Duration| format!("{:.1}", duration.as_secs_f64() * 1000.0);
        let picture = self.picture.map_or_else(
            || String::from("waiting for the first frame"),
            |(codec, width, height)| format!("{codec} {width}x{height}"),
        );
        let stages = &snap.stages;
        let latency = stages.total().saturating_add(snap.rtt / 2);
        vec![
            ("Agent", self.agent.clone()),
            ("Path", format!("{}, RTT {} ms", self.path, ms(snap.rtt))),
            (
                "Video",
                format!(
                    "{picture}, {:.1} Mbit/s, {:.0} fps shown / {:.0} received",
                    snap.mbit_per_s, snap.shown_fps, snap.received_fps
                ),
            ),
            ("Encoder", self.encoder.clone()),
            ("Decoder", String::from(OpenH264Decoder::NAME)),
            ("Display", self.display.clone()),
            (
                "Agent ms",
                format!(
                    "capture {}  convert {}  encode {}",
                    ms(stages.capture),
                    ms(stages.convert),
                    ms(stages.encode)
                ),
            ),
            (
                "Viewer ms",
                format!(
                    "queue {}  decode {}  render {}",
                    ms(stages.queue),
                    ms(stages.decode),
                    ms(stages.render)
                ),
            ),
            (
                "Latency",
                format!("~{} ms + display (stages + RTT/2)", ms(latency)),
            ),
            (
                "Dropped/s",
                format!(
                    "folded {}  replaced {}  discarded {}  (decode errors: {})",
                    snap.folded, snap.replaced, snap.discarded, snap.errors
                ),
            ),
            ("Keys", String::from(self.keys)),
        ]
    }

    pub fn ui(&self, ui: &egui::Ui) {
        let rows = self.rows();
        egui::Area::new(egui::Id::unique("rr-viewer stats overlay"))
            .anchor(egui::Align2::LEFT_TOP, [8.0, 8.0])
            .interactable(false)
            .show(ui.ctx(), |ui| {
                egui::Frame::new()
                    .fill(egui::Color32::from_black_alpha(200))
                    .inner_margin(8.0)
                    .corner_radius(4.0)
                    .show(ui, |ui| {
                        egui::Grid::new("stats-grid")
                            .num_columns(2)
                            .spacing([12.0, 2.0])
                            .show(ui, |ui| {
                                for (label, value) in rows {
                                    ui.label(
                                        egui::RichText::new(label)
                                            .monospace()
                                            .color(egui::Color32::LIGHT_GRAY),
                                    );
                                    ui.label(
                                        egui::RichText::new(value)
                                            .monospace()
                                            .color(egui::Color32::WHITE),
                                    );
                                    ui.end_row();
                                }
                            });
                    });
            });
    }
}
