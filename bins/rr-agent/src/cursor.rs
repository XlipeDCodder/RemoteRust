//! The Agent's pointer for the Viewer (blueprint v2 §6.2): polled about
//! 60 times a second on its own thread. Positions go out when they change;
//! each shape goes out once and is then referred to by id.
//!
//! Nothing here waits for the network: when the channel to the sending
//! task is full, the update is retried on the next poll, so a slow link
//! only delays the pointer.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use rr_net::CursorSender;
use rr_platform::cursor::{self, Pointer, Shape};
use rr_platform::input::{Area, SharedArea};
use rr_proto::cursor::CACHED_SHAPES;
use rr_proto::{BoundedBytes, CursorMsg};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

/// Time between two polls.
const POLL: Duration = Duration::from_millis(16);
/// Pause after a failed poll (e.g. while the secure desktop is shown).
const ERROR_RETRY: Duration = Duration::from_millis(500);

/// Sends the updates from the cursor thread until either side ends.
pub async fn send(mut sender: CursorSender, mut updates: mpsc::Receiver<CursorMsg>) {
    while let Some(msg) = updates.recv().await {
        if let Err(err) = sender.send(&msg).await {
            tracing::debug!(error = %err, "cursor stream closed");
            return;
        }
    }
}

/// The cursor thread; stopped and waited for on drop.
pub struct CursorThread {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl CursorThread {
    /// Starts following the pointer over the monitor that `area` tracks.
    ///
    /// # Errors
    /// The thread could not be started.
    pub fn start(area: SharedArea, out: mpsc::Sender<CursorMsg>) -> std::io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("rr-cursor".to_owned())
            .spawn(move || run(&area, &out, &thread_stop))?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for CursorThread {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            tracing::error!("the cursor thread panicked");
        }
    }
}

fn run(area: &SharedArea, out: &mpsc::Sender<CursorMsg>, stop: &AtomicBool) {
    let mut source = match cursor::open() {
        Ok(Some(source)) => source,
        Ok(None) => {
            tracing::debug!("the pointer is drawn into the video");
            return;
        }
        Err(err) => {
            tracing::warn!(error = %err, "cannot follow the pointer; the viewer will not see it");
            return;
        }
    };
    let mut follower = Follower::default();
    let mut failing = false;
    while !stop.load(Ordering::Relaxed) {
        match source.poll() {
            Ok((pointer, shape)) => {
                failing = false;
                if follower.update(pointer, shape, area.get(), out).is_err() {
                    return; // the session is over
                }
            }
            Err(err) => {
                if !failing {
                    tracing::debug!(error = %err, "cannot read the pointer, retrying");
                    failing = true;
                }
                std::thread::sleep(ERROR_RETRY);
                continue;
            }
        }
        std::thread::sleep(POLL);
    }
}

/// The receiving side is gone.
struct Closed;

/// What the Viewer was last told.
#[derive(Default)]
struct Follower {
    cache: ShapeCache,
    /// A shape the Viewer has not been sent yet.
    pending: Option<Shape>,
    sent_position: Option<CursorMsg>,
}

impl Follower {
    fn update(
        &mut self,
        pointer: Pointer,
        shape: Option<Shape>,
        area: Option<Area>,
        out: &mpsc::Sender<CursorMsg>,
    ) -> Result<(), Closed> {
        if shape.is_some() {
            self.pending = shape;
        }
        // The shape goes first, so the Viewer never shows a stale one at a
        // new position for long.
        if let Some(shape) = self.pending.take() {
            let msg = self.cache.message(&shape);
            match out.try_send(msg.clone()) {
                Ok(()) => self.cache.sent(shape, &msg),
                Err(TrySendError::Full(_)) => {
                    self.pending = Some(shape);
                    return Ok(());
                }
                Err(TrySendError::Closed(_)) => return Err(Closed),
            }
        }
        let position = position(pointer, area);
        if self.sent_position.as_ref() == Some(&position) {
            return Ok(());
        }
        match out.try_send(position.clone()) {
            Ok(()) => self.sent_position = Some(position),
            Err(TrySendError::Full(_)) => {} // retried on the next poll
            Err(TrySendError::Closed(_)) => return Err(Closed),
        }
        Ok(())
    }
}

/// The position message: protocol coordinates on the captured monitor,
/// hidden when the pointer is elsewhere or the system hides it.
fn position(pointer: Pointer, area: Option<Area>) -> CursorMsg {
    match area.and_then(|area| area.coords(pointer.x, pointer.y)) {
        Some((x, y)) => CursorMsg::Position {
            x,
            y,
            visible: pointer.visible,
        },
        None => CursorMsg::Position {
            x: 0,
            y: 0,
            visible: false,
        },
    }
}

/// The shapes the Viewer has, oldest first (see [`CACHED_SHAPES`]).
#[derive(Default)]
struct ShapeCache {
    entries: VecDeque<(u32, Shape)>,
    next_id: u32,
}

impl ShapeCache {
    /// The message that makes the Viewer show `shape`.
    fn message(&self, shape: &Shape) -> CursorMsg {
        if let Some((id, _)) = self.entries.iter().find(|(_, cached)| cached == shape) {
            return CursorMsg::UseCachedShape { id: *id };
        }
        CursorMsg::Shape {
            id: self.next_id,
            hot_x: shape.hot_x,
            hot_y: shape.hot_y,
            width: shape.width,
            height: shape.height,
            // `Shape` is at most 256 × 256, the protocol's limit.
            rgba: BoundedBytes::new(shape.rgba.clone()).unwrap_or_default(),
        }
    }

    /// Records that `msg`, made by [`ShapeCache::message`], was sent.
    fn sent(&mut self, shape: Shape, msg: &CursorMsg) {
        if let CursorMsg::Shape { id, .. } = msg {
            self.entries.push_back((*id, shape));
            if self.entries.len() > CACHED_SHAPES {
                self.entries.pop_front();
            }
            self.next_id = self.next_id.wrapping_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape(color: u8) -> Shape {
        Shape {
            width: 1,
            height: 1,
            hot_x: 0,
            hot_y: 0,
            rgba: vec![color, color, color, 255],
        }
    }

    const AREA: Area = Area {
        left: 100,
        top: 0,
        width: 1000,
        height: 500,
    };

    fn pointer(x: i32, y: i32) -> Pointer {
        Pointer {
            x,
            y,
            visible: true,
        }
    }

    #[test]
    fn shapes_are_sent_once_then_by_id() {
        let mut cache = ShapeCache::default();
        let first = cache.message(&shape(1));
        assert!(matches!(first, CursorMsg::Shape { id: 0, .. }));
        cache.sent(shape(1), &first);
        let second = cache.message(&shape(2));
        cache.sent(shape(2), &second);
        assert!(matches!(second, CursorMsg::Shape { id: 1, .. }));
        assert_eq!(
            cache.message(&shape(1)),
            CursorMsg::UseCachedShape { id: 0 }
        );
    }

    #[test]
    fn the_cache_forgets_the_oldest_shape() {
        let mut cache = ShapeCache::default();
        for color in 0..=u8::try_from(CACHED_SHAPES).unwrap() {
            let msg = cache.message(&shape(color));
            cache.sent(shape(color), &msg);
        }
        assert!(matches!(cache.message(&shape(0)), CursorMsg::Shape { .. }));
        assert_eq!(
            cache.message(&shape(1)),
            CursorMsg::UseCachedShape { id: 1 }
        );
    }

    #[test]
    fn positions_are_sent_on_change_and_hidden_off_the_monitor() {
        let (tx, mut rx) = mpsc::channel(8);
        let mut follower = Follower::default();
        let _ = follower.update(pointer(100, 0), Some(shape(1)), Some(AREA), &tx);
        let _ = follower.update(pointer(100, 0), None, Some(AREA), &tx);
        let _ = follower.update(pointer(50, 0), None, Some(AREA), &tx);
        assert!(matches!(
            rx.try_recv().unwrap(),
            CursorMsg::Shape { id: 0, .. }
        ));
        assert_eq!(
            rx.try_recv().unwrap(),
            CursorMsg::Position {
                x: 32,
                y: 65,
                visible: true
            }
        );
        assert_eq!(
            rx.try_recv().unwrap(),
            CursorMsg::Position {
                x: 0,
                y: 0,
                visible: false
            }
        );
        assert!(
            rx.try_recv().is_err(),
            "an unchanged position is not resent"
        );
    }

    #[test]
    fn a_full_channel_delays_updates_without_losing_the_shape() {
        let (tx, mut rx) = mpsc::channel(1);
        let mut follower = Follower::default();
        tx.try_send(CursorMsg::UseCachedShape { id: 9 }).unwrap();
        assert!(
            follower
                .update(pointer(100, 0), Some(shape(1)), Some(AREA), &tx)
                .is_ok()
        );
        assert_eq!(rx.try_recv().unwrap(), CursorMsg::UseCachedShape { id: 9 });
        // Next poll: the shape still goes out, before the position.
        let _ = follower.update(pointer(100, 0), None, Some(AREA), &tx);
        assert!(matches!(
            rx.try_recv().unwrap(),
            CursorMsg::Shape { id: 0, .. }
        ));
        let _ = follower.update(pointer(100, 0), None, Some(AREA), &tx);
        assert!(matches!(rx.try_recv().unwrap(), CursorMsg::Position { .. }));
        drop(rx);
        assert!(
            follower
                .update(pointer(101, 0), None, Some(AREA), &tx)
                .is_err()
        );
    }
}
