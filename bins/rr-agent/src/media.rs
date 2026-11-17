//! The Agent media pipeline for one session (blueprint v2 §4.3, §8.1,
//! §8.2): capture → BGRA→I420 → H.264 on a dedicated thread, frames sent
//! from the async side.
//!
//! The capture thread also owns the session's input and cursor threads
//! (see [`crate::input`] and [`crate::cursor`]): on Wayland the screen and
//! the input come from one portal session, and both need the captured
//! monitor's position, which only the capturer knows.
//!
//! "Latest frame wins": the capture thread only grabs the screen once the
//! network has taken the previous frame (a one-permit semaphore). While it
//! waits, DXGI folds screen updates together, so the next frame always
//! shows the current screen and nothing ever queues.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rr_media::{EncoderSettings, I420, OpenH264Encoder, VideoEncoder, bgra_to_i420};
use rr_net::{AgentSession, SessionEvent, monotonic_us};
use rr_platform::capture::{self, CaptureError, Screen};
use rr_platform::input::{Area, InputBackend, InputError};
use rr_proto::{AgentTimings, Codec, CursorMsg, DisconnectReason, VideoFrameHeader};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

use crate::cursor::{self, CursorThread};
use crate::input::{self, InputThread, Queue};

/// Frame rate cap for the software path (blueprint v2 §2.3: ≥ 30 fps).
pub const MAX_FPS: u8 = 30;

/// Longest wait for a screen change before checking for stop/keyframes.
const CAPTURE_WAIT: Duration = Duration::from_millis(100);
/// Minimum spacing of forced keyframes, however often the Viewer asks.
const KEYFRAME_SPACING: Duration = Duration::from_millis(250);
/// Pause before retrying after the capture was interrupted (desktop
/// switch, secure desktop).
const ACCESS_LOST_RETRY: Duration = Duration::from_millis(250);
/// Pointer updates waiting for the network (the cursor thread retries
/// when this is full).
const CURSOR_QUEUE: usize = 8;

/// One encoded frame on its way to the network, holding the "network
/// busy" permit until it has been written.
struct Encoded {
    header: VideoFrameHeader,
    bitstream: Vec<u8>,
    _permit: OwnedSemaphorePermit,
}

/// Flags shared between the async side and the capture thread.
#[derive(Default)]
struct Flags {
    keyframe: AtomicBool,
    stop: AtomicBool,
}

/// Streams monitor `monitor` until the session ends.
pub async fn run_session(mut session: AgentSession, monitor: u8) {
    let handle = session.handle();
    let viewer = session.viewer_name().to_owned();
    let flags = Arc::new(Flags {
        keyframe: AtomicBool::new(true),
        stop: AtomicBool::new(false),
    });
    let network_idle = Arc::new(Semaphore::new(1));
    let (frames_tx, mut frames_rx) = mpsc::channel::<Encoded>(1);
    let (recycle_tx, recycle_rx) = std::sync::mpsc::channel::<Vec<u8>>();

    // Remote control: the network side fills the queue from the start; the
    // capture thread starts injecting once the screen (and, on Wayland, the
    // portal's input) is open.
    let control = session.take_input().map(|receiver| {
        let queue = Arc::new(Queue::default());
        let reader = tokio::spawn(input::read(receiver, Arc::clone(&queue), handle.clone()));
        (queue, reader)
    });
    let (cursor_tx, cursor_rx) = mpsc::channel::<CursorMsg>(CURSOR_QUEUE);
    let cursor_task = session
        .take_cursor()
        .map(|sender| tokio::spawn(cursor::send(sender, cursor_rx)));

    let pipeline = Pipeline {
        monitor,
        flags: Arc::clone(&flags),
        network_idle: Arc::clone(&network_idle),
        frames: frames_tx,
        recycled: recycle_rx,
        runtime: tokio::runtime::Handle::current(),
        input: control.as_ref().map(|(queue, _)| Arc::clone(queue)),
        cursor: cursor_tx,
    };
    let thread = std::thread::Builder::new()
        .name("rr-capture".to_owned())
        .spawn(move || pipeline.run());
    let thread = match thread {
        Ok(thread) => thread,
        Err(err) => {
            tracing::error!(error = %err, "cannot start the capture thread");
            handle.end(DisconnectReason::MediaFailed);
            return;
        }
    };

    loop {
        tokio::select! {
            frame = frames_rx.recv() => {
                let Some(frame) = frame else { break };
                if let Err(err) = session.video.send(&frame.header, &frame.bitstream).await {
                    tracing::debug!(error = %err, "video stream closed");
                    break;
                }
                let _ = recycle_tx.send(frame.bitstream);
            }
            event = session.next_event() => match event {
                Some(SessionEvent::KeyframeRequested) => {
                    flags.keyframe.store(true, Ordering::Relaxed);
                }
                None => break,
            },
        }
    }

    flags.stop.store(true, Ordering::Relaxed);
    network_idle.close();
    drop(frames_rx);
    if let Some((queue, reader)) = control {
        reader.abort();
        queue.end();
    }
    if let Some(task) = cursor_task {
        task.abort();
    }
    let joined = tokio::task::spawn_blocking(move || thread.join()).await;
    match joined {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(PipelineError::Capture(CaptureError::Denied)))) => {
            println!("  Screen sharing was declined or stopped in the system dialog.");
            tracing::info!(%viewer, "screen sharing declined in the system dialog");
            handle.end(DisconnectReason::ConsentDenied);
        }
        Ok(Ok(Err(err))) => {
            tracing::error!(error = %err, "screen capture failed");
            handle.end(DisconnectReason::MediaFailed);
        }
        Ok(Err(_)) | Err(_) => {
            tracing::error!("the capture thread panicked");
            handle.end(DisconnectReason::MediaFailed);
        }
    }
    tracing::info!(%viewer, "screen sharing stopped");
}

/// Everything the capture thread owns.
struct Pipeline {
    monitor: u8,
    flags: Arc<Flags>,
    network_idle: Arc<Semaphore>,
    frames: mpsc::Sender<Encoded>,
    recycled: std::sync::mpsc::Receiver<Vec<u8>>,
    runtime: tokio::runtime::Handle,
    /// Input from the Viewer, when control was granted.
    input: Option<Arc<Queue>>,
    /// Pointer updates for the Viewer.
    cursor: mpsc::Sender<CursorMsg>,
}

/// Why the capture thread stopped with an error.
#[derive(Debug, thiserror::Error)]
enum PipelineError {
    #[error(transparent)]
    Capture(#[from] CaptureError),
    #[error(transparent)]
    Media(#[from] rr_media::MediaError),
    #[error("picture too large for the protocol")]
    TooLarge,
}

/// Session totals for the "capture stopped" log line.
#[derive(Default)]
struct Totals {
    sent: u64,
    rate_skips: u64,
    folded: u64,
}

impl Pipeline {
    fn run(self) -> Result<(), PipelineError> {
        let mut totals = Totals::default();
        let result = self.stream(&mut totals);
        tracing::info!(
            sent = totals.sent,
            rate_skips = totals.rate_skips,
            folded = totals.folded,
            "capture stopped"
        );
        result
    }

    fn stream(&self, totals: &mut Totals) -> Result<(), PipelineError> {
        let Screen {
            mut capturer,
            input,
            area,
        } = capture::open_screen(self.monitor, self.input.is_some())?;
        // Declared after the capturer, so dropped before it: input and the
        // pointer stop first, then (on Wayland) the portal session closes.
        let _input = self.start_input(input);
        let _cursor = CursorThread::start(area.clone(), self.cursor.clone())
            .inspect_err(|err| tracing::warn!(error = %err, "cannot start the cursor thread"))
            .ok();
        let mut encoder = OpenH264Encoder::new(&EncoderSettings {
            max_fps: MAX_FPS,
            ..EncoderSettings::default()
        })?;
        let interval = Duration::from_secs(1) / u32::from(MAX_FPS);
        let mut picture = I420::default();
        let mut have_picture = false;
        // The latest picture has not been sent yet (new, or skipped by the
        // rate controller).
        let mut unsent = false;
        let mut keyframe_pending = false;
        let mut last_keyframe: Option<Instant> = None;
        // When the picture of the last encode (sent or skipped) was
        // grabbed, or polled for when it was not new. Pacing counts from
        // there, so capture and conversion time fall inside the interval.
        let mut last_encode: Option<Instant> = None;
        let mut frame_id = 0u64;
        let mut folded = 0u32;
        let mut timings = AgentTimings::default();
        let mut capture_ts_us = 0u64;

        while !self.flags.stop.load(Ordering::Relaxed) {
            // Pace encodes to MAX_FPS, retries after a rate-control skip
            // included.
            if let Some(remaining) = last_encode.and_then(|at| interval.checked_sub(at.elapsed())) {
                std::thread::sleep(remaining);
            }
            // Wait until the network took the previous frame.
            let permit = self.runtime.block_on(async {
                tokio::time::timeout(CAPTURE_WAIT, Arc::clone(&self.network_idle).acquire_owned())
                    .await
            });
            let permit = match permit {
                Ok(Ok(permit)) => permit,
                Ok(Err(_)) => return Ok(()), // closed: the session is over
                Err(_) => continue,          // still sending; check `stop`
            };

            // Grab the screen if it changed. When a picture is waiting to
            // be (re)sent, only poll.
            let wait = if unsent { Duration::ZERO } else { CAPTURE_WAIT };
            let mut converted = Ok(());
            let mut grabbed = Instant::now();
            let captured = capturer.capture(wait, &mut |frame| {
                grabbed = frame.acquired;
                let started = Instant::now();
                capture_ts_us = monotonic_us();
                timings.capture_us = micros(started.saturating_duration_since(frame.acquired));
                converted = bgra_to_i420(
                    frame.bgra,
                    frame.stride,
                    frame.width as usize,
                    frame.height as usize,
                    &mut picture,
                );
                timings.convert_us = micros(started.elapsed());
                folded = folded.saturating_add(frame.accumulated.saturating_sub(1));
            });
            // The monitor may have moved or changed resolution.
            area.set(Area::of(capturer.monitor()));
            match captured {
                Ok(true) => {
                    converted?;
                    have_picture = true;
                    unsent = true;
                }
                Ok(false) => {}
                Err(CaptureError::AccessLost) => {
                    tracing::debug!("capture interrupted, retrying");
                    std::thread::sleep(ACCESS_LOST_RETRY);
                    continue;
                }
                Err(err) => return Err(err.into()),
            }

            if self.flags.keyframe.swap(false, Ordering::Relaxed) {
                keyframe_pending = true;
            }
            let keyframe_due =
                keyframe_pending && last_keyframe.is_none_or(|at| at.elapsed() >= KEYFRAME_SPACING);
            if !have_picture || !(unsent || keyframe_due) {
                continue;
            }

            let mut bitstream = self.recycled.try_recv().unwrap_or_default();
            let started = Instant::now();
            let info = encoder.encode(&picture, keyframe_due, &mut bitstream)?;
            timings.encode_us = micros(started.elapsed());
            last_encode = Some(grabbed);
            if bitstream.is_empty() {
                // Skipped by the rate controller: retry with the latest
                // picture on the next round.
                totals.rate_skips += 1;
                unsent = true;
                continue;
            }
            if info.keyframe {
                keyframe_pending = false;
                last_keyframe = Some(Instant::now());
            }
            unsent = false;

            totals.folded += u64::from(folded);
            let header = VideoFrameHeader {
                frame_id,
                capture_ts_us,
                keyframe: info.keyframe,
                codec: Codec::H264,
                width: u16::try_from(picture.width()).map_err(|_| PipelineError::TooLarge)?,
                height: u16::try_from(picture.height()).map_err(|_| PipelineError::TooLarge)?,
                timings,
                skipped: std::mem::take(&mut folded),
                len: u32::try_from(bitstream.len()).map_err(|_| PipelineError::TooLarge)?,
            };
            let frame = Encoded {
                header,
                bitstream,
                _permit: permit,
            };
            if self.frames.blocking_send(frame).is_err() {
                return Ok(()); // the session is over
            }
            frame_id = frame_id.saturating_add(1);
            totals.sent += 1;
        }
        Ok(())
    }
}

impl Pipeline {
    /// Starts injecting the Viewer's input, if control was granted and
    /// this system allows it. Without it the session stays view only.
    fn start_input(
        &self,
        backend: Option<Result<Box<dyn InputBackend>, InputError>>,
    ) -> Option<InputThread> {
        let queue = self.input.as_ref()?;
        let started = match backend? {
            Ok(backend) => InputThread::start(backend, Arc::clone(queue), self.monitor)
                .map_err(|err| err.to_string()),
            Err(InputError::Denied) => Err("not allowed in the system dialog".to_owned()),
            Err(err) => Err(err.to_string()),
        };
        match started {
            Ok(thread) => Some(thread),
            Err(reason) => {
                println!("  Remote control is unavailable ({reason}); the session is view only.");
                tracing::warn!(%reason, "remote control unavailable");
                None
            }
        }
    }
}

fn micros(duration: Duration) -> u32 {
    u32::try_from(duration.as_micros()).unwrap_or(u32::MAX)
}
