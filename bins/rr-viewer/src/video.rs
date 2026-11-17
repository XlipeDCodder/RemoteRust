//! Video reception and decoding (blueprint v2 §4.3, §8.5).
//!
//! A network task reads frames; a decode thread turns them into pictures;
//! the newest picture waits in a mailbox for the window to draw it.
//!
//! Encoded frames are never dropped before decoding, because each one
//! depends on the previous ones. When decoding falls behind, the one-slot
//! channel stops the reader, QUIC flow control slows the Agent down, and
//! the Agent folds screen updates into fewer frames. Decoded pictures, on
//! the other hand, are replaced freely when the window is slower.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, mpsc as std_mpsc};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use rr_media::{I420, Mailbox, OpenH264Decoder, VideoDecoder as _};
use rr_net::{SessionControl, VideoReceiver};
use rr_proto::VideoFrameHeader;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use winit::event_loop::EventLoopProxy;

use crate::window::UserEvent;

/// How often to repeat a keyframe request while waiting for one.
const KEYFRAME_RETRY: Duration = Duration::from_secs(1);

/// A decoded picture and what is known about its trip.
pub struct Decoded {
    pub picture: I420,
    pub header: VideoFrameHeader,
    /// Time between reception and the start of decoding.
    pub queued: Duration,
    /// Decoding time.
    pub decode: Duration,
    /// When decoding finished.
    pub decoded_at: Instant,
}

/// Counters shared with the overlay.
#[derive(Debug, Default)]
pub struct Counters {
    /// Bitstream bytes received.
    pub bytes: AtomicU64,
    /// Frames received.
    pub frames: AtomicU64,
    /// Screen updates the Agent folded into later frames.
    pub folded: AtomicU64,
    /// Frames thrown away while waiting for a keyframe.
    pub discarded: AtomicU64,
    /// Frames that failed to decode.
    pub errors: AtomicU64,
}

impl Counters {
    fn add(counter: &AtomicU64, value: u64) {
        counter.fetch_add(value, Ordering::Relaxed);
    }
}

/// A frame as received.
struct Received {
    header: VideoFrameHeader,
    bitstream: Vec<u8>,
    at: Instant,
}

/// The running receive and decode stages.
pub struct Pipeline {
    pub mailbox: Arc<Mailbox<Decoded>>,
    pub counters: Arc<Counters>,
    reader: JoinHandle<()>,
    decoder: Option<thread::JoinHandle<()>>,
}

impl Pipeline {
    /// Starts reading `video` on `runtime` and decoding on a new thread.
    /// The window is woken through `proxy` for each picture.
    pub fn start(
        runtime: &tokio::runtime::Handle,
        video: VideoReceiver,
        control: SessionControl,
        proxy: EventLoopProxy<UserEvent>,
    ) -> anyhow::Result<Self> {
        let decoder = OpenH264Decoder::new().context("cannot create the video decoder")?;
        let mailbox = Arc::new(Mailbox::new());
        let counters = Arc::new(Counters::default());
        let (frames_tx, frames_rx) = mpsc::channel(1);
        // Bitstream buffers travel back to the reader to be reused.
        let (spare_tx, spare_rx) = std_mpsc::sync_channel(2);

        let reader = runtime.spawn(read(
            video,
            frames_tx,
            spare_rx,
            Arc::clone(&counters),
            proxy.clone(),
        ));
        let decode_stage = DecodeStage {
            decoder,
            frames: frames_rx,
            spares: spare_tx,
            mailbox: Arc::clone(&mailbox),
            counters: Arc::clone(&counters),
            control,
            proxy,
        };
        let decoder = thread::Builder::new()
            .name("rr-decode".into())
            .spawn(move || decode_stage.run())
            .context("cannot start the decode thread")?;
        Ok(Self {
            mailbox,
            counters,
            reader,
            decoder: Some(decoder),
        })
    }

    /// Stops both stages. Call with the runtime still running.
    pub fn stop(mut self) {
        // Ending the reader drops the channel sender, which ends the
        // decode thread.
        self.reader.abort();
        if let Some(decoder) = self.decoder.take() {
            let _ = decoder.join();
        }
    }
}

async fn read(
    mut video: VideoReceiver,
    frames: mpsc::Sender<Received>,
    spares: std_mpsc::Receiver<Vec<u8>>,
    counters: Arc<Counters>,
    proxy: EventLoopProxy<UserEvent>,
) {
    loop {
        let mut bitstream = spares.try_recv().unwrap_or_default();
        let header = match video.recv(&mut bitstream).await {
            Ok(header) => header,
            Err(err) => {
                tracing::debug!(error = %err, "video stream ended");
                let _ = proxy.send_event(UserEvent::VideoFailed(err.to_string()));
                return;
            }
        };
        Counters::add(&counters.bytes, u64::from(header.len));
        Counters::add(&counters.frames, 1);
        Counters::add(&counters.folded, u64::from(header.skipped));
        let frame = Received {
            header,
            bitstream,
            at: Instant::now(),
        };
        if frames.send(frame).await.is_err() {
            return;
        }
    }
}

struct DecodeStage {
    decoder: OpenH264Decoder,
    frames: mpsc::Receiver<Received>,
    spares: std_mpsc::SyncSender<Vec<u8>>,
    mailbox: Arc<Mailbox<Decoded>>,
    counters: Arc<Counters>,
    control: SessionControl,
    proxy: EventLoopProxy<UserEvent>,
}

impl DecodeStage {
    fn run(mut self) {
        // The stream starts with a keyframe; after a decode error, frames
        // are useless until the next one.
        let mut need_keyframe = true;
        let mut asked: Option<Instant> = None;
        let mut spare: Option<I420> = None;
        while let Some(Received {
            header,
            bitstream,
            at,
        }) = self.frames.blocking_recv()
        {
            if need_keyframe && !header.keyframe {
                Counters::add(&self.counters.discarded, 1);
                if asked.is_none_or(|when| when.elapsed() >= KEYFRAME_RETRY) {
                    self.control.request_keyframe();
                    asked = Some(Instant::now());
                }
                let _ = self.spares.try_send(bitstream);
                continue;
            }

            let started = Instant::now();
            let mut picture = spare
                .take()
                .or_else(|| self.mailbox.spare().map(|old| old.picture))
                .unwrap_or_default();
            let result = self.decoder.decode(&bitstream, &mut picture);
            let _ = self.spares.try_send(bitstream);
            match result {
                Ok(true) => {
                    need_keyframe = false;
                    let decoded_at = Instant::now();
                    let frame = Decoded {
                        picture,
                        header,
                        queued: started.saturating_duration_since(at),
                        decode: decoded_at.saturating_duration_since(started),
                        decoded_at,
                    };
                    if let Some(replaced) = self.mailbox.put(frame) {
                        spare = Some(replaced.picture);
                    }
                    if self.proxy.send_event(UserEvent::Frame).is_err() {
                        return; // the window is gone
                    }
                }
                Ok(false) => spare = Some(picture),
                Err(err) => {
                    Counters::add(&self.counters.errors, 1);
                    tracing::warn!(
                        error = %err,
                        frame = header.frame_id,
                        "cannot decode a frame; asking for a keyframe"
                    );
                    spare = Some(picture);
                    need_keyframe = true;
                    self.control.request_keyframe();
                    asked = Some(Instant::now());
                }
            }
        }
    }
}
