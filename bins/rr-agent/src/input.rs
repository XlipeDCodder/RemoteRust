//! Remote control on the Agent (blueprint v2 §8.7): the Viewer's keyboard
//! and mouse, replayed through an [`Injector`] on a dedicated thread.
//!
//! Nothing may stay pressed on this machine. Everything held is released:
//! - on `ReleaseAll` from the Viewer (it sends one when it loses focus);
//! - when the input stream or the session ends;
//! - by a watchdog: while something is held the Viewer sends `Held` every
//!   250 ms, and one second without any input releases everything. That
//!   covers a pulled cable, which QUIC only notices after its idle timeout.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use rr_net::{InputReceiver, SessionError, SessionHandle};
use rr_platform::input::{Injector, InputBackend, InputError};
use rr_proto::{DisconnectReason, InputMsg};

/// Silence, while something is held, that releases everything.
pub const WATCHDOG: Duration = Duration::from_secs(1);
/// How often the input thread checks the watchdog when idle.
const TICK: Duration = Duration::from_millis(100);
/// Waiting messages past which the injector is considered stuck.
const MAX_QUEUED: usize = 1024;
/// Least time between two logs of injection failures.
const FAILURE_LOG_PERIOD: Duration = Duration::from_secs(5);

#[derive(Default)]
struct State {
    events: VecDeque<InputMsg>,
    /// When the last message of any kind arrived.
    last_seen: Option<Instant>,
    ended: bool,
    coalesced: u64,
    overflows: u64,
}

/// Messages from the network task to the input thread.
#[derive(Default)]
pub struct Queue {
    state: Mutex<State>,
    wake: Condvar,
}

impl Queue {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Adds one message. A pointer move replaces a move still waiting;
    /// `Held` only proves that the Viewer is alive. Keys and buttons are
    /// never merged or dropped, unless the injector is stuck: then the
    /// backlog is replaced by a release of everything.
    pub fn push(&self, msg: InputMsg) {
        let mut state = self.lock();
        state.last_seen = Some(Instant::now());
        match msg {
            InputMsg::Held => return,
            InputMsg::MouseMove { .. }
                if matches!(state.events.back(), Some(InputMsg::MouseMove { .. })) =>
            {
                if let Some(last) = state.events.back_mut() {
                    *last = msg;
                }
                state.coalesced += 1;
            }
            _ if state.events.len() >= MAX_QUEUED => {
                state.events.clear();
                state.events.push_back(InputMsg::ReleaseAll);
                state.overflows += 1;
            }
            _ => state.events.push_back(msg),
        }
        drop(state);
        self.wake.notify_one();
    }

    /// No more messages will come; the input thread releases everything
    /// and stops.
    pub fn end(&self) {
        self.lock().ended = true;
        self.wake.notify_one();
    }

    /// Waits up to `timeout` for messages and moves them into `batch`.
    /// Returns whether the queue ended and when the last message arrived.
    fn take(&self, timeout: Duration, batch: &mut Vec<InputMsg>) -> (bool, Option<Instant>) {
        let mut state = self.lock();
        if state.events.is_empty() && !state.ended {
            state = self
                .wake
                .wait_timeout(state, timeout)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        batch.extend(state.events.drain(..));
        (state.ended, state.last_seen)
    }
}

/// Reads the Viewer's input into `queue` until the stream or the session
/// ends. A flood of keys or malformed input ends the session.
pub async fn read(mut input: InputReceiver, queue: Arc<Queue>, handle: SessionHandle) {
    loop {
        match input.recv().await {
            Ok(Some(msg)) => queue.push(msg),
            Ok(None) => {
                tracing::debug!("the viewer closed its input stream");
                break;
            }
            Err(SessionError::Protocol(reason)) => {
                tracing::warn!(reason, "bad input from the viewer: ending the session");
                handle.end(DisconnectReason::ProtocolError);
                break;
            }
            Err(err) => {
                tracing::debug!(error = %err, "input stream closed");
                break;
            }
        }
    }
    queue.end();
    if input.dropped() > 0 {
        tracing::info!(
            dropped = input.dropped(),
            "pointer moves over the rate cap were dropped"
        );
    }
}

/// The input thread; ends the queue and waits for the thread on drop.
pub struct InputThread {
    queue: Arc<Queue>,
    thread: Option<JoinHandle<()>>,
}

impl InputThread {
    /// Starts injecting what arrives in `queue` through `backend`, keeping
    /// only pointer moves aimed at `monitor`.
    ///
    /// # Errors
    /// The thread could not be started.
    pub fn start(
        backend: Box<dyn InputBackend>,
        queue: Arc<Queue>,
        monitor: u8,
    ) -> std::io::Result<Self> {
        let thread_queue = Arc::clone(&queue);
        let thread = std::thread::Builder::new()
            .name("rr-input".to_owned())
            .spawn(move || run(Injector::new(backend), &thread_queue, monitor))?;
        Ok(Self {
            queue,
            thread: Some(thread),
        })
    }
}

impl Drop for InputThread {
    fn drop(&mut self) {
        self.queue.end();
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            tracing::error!("the input thread panicked");
        }
    }
}

/// Session totals for the "remote control stopped" log line.
#[derive(Debug, Default)]
struct Totals {
    keys: u64,
    moves: u64,
    buttons: u64,
    wheel: u64,
    releases: u64,
    watchdog: u64,
    failures: u64,
    other_monitor: u64,
}

/// Logs injection failures without flooding the log.
#[derive(Default)]
struct Failures {
    last_log: Option<Instant>,
    since_log: u64,
}

impl Failures {
    fn note(&mut self, totals: &mut Totals, err: &InputError) {
        totals.failures += 1;
        self.since_log += 1;
        if self
            .last_log
            .is_none_or(|at| at.elapsed() >= FAILURE_LOG_PERIOD)
        {
            tracing::warn!(error = %err, count = self.since_log, "input injection failed");
            self.last_log = Some(Instant::now());
            self.since_log = 0;
        }
    }
}

fn run(mut injector: Injector, queue: &Queue, monitor: u8) {
    tracing::info!(backend = injector.name(), "remote control ready");
    let mut totals = Totals::default();
    let mut failures = Failures::default();
    let mut batch = Vec::new();
    loop {
        let (ended, last_seen) = queue.take(TICK, &mut batch);
        for msg in batch.drain(..) {
            if let Err(err) = apply(&mut injector, &mut totals, msg, monitor) {
                failures.note(&mut totals, &err);
            }
        }
        if ended {
            break;
        }
        if injector.holding() && last_seen.is_none_or(|at| at.elapsed() >= WATCHDOG) {
            tracing::warn!(
                "no input from the viewer for 1 s while keys or buttons were held: released them"
            );
            totals.watchdog += 1;
            if let Err(err) = injector.release_all() {
                failures.note(&mut totals, &err);
            }
        }
    }
    if let Err(err) = injector.release_all() {
        failures.note(&mut totals, &err);
    }
    let state = queue.lock();
    tracing::info!(
        keys = totals.keys,
        moves = totals.moves,
        coalesced = state.coalesced,
        buttons = totals.buttons,
        wheel = totals.wheel,
        releases = totals.releases,
        watchdog = totals.watchdog,
        other_monitor = totals.other_monitor,
        overflows = state.overflows,
        failures = totals.failures,
        "remote control stopped"
    );
}

fn apply(
    injector: &mut Injector,
    totals: &mut Totals,
    msg: InputMsg,
    monitor: u8,
) -> Result<(), InputError> {
    match msg {
        InputMsg::Key { code, down } => {
            totals.keys += 1;
            injector.key(code, down)
        }
        InputMsg::MouseMove {
            monitor: target,
            x,
            y,
        } => {
            if target == monitor {
                totals.moves += 1;
                injector.move_to(x, y)
            } else {
                totals.other_monitor += 1;
                Ok(())
            }
        }
        InputMsg::MouseButton { button, down } => {
            totals.buttons += 1;
            injector.button(button, down)
        }
        InputMsg::Wheel { dx, dy } => {
            totals.wheel += 1;
            injector.wheel(i32::from(dx), i32::from(dy))
        }
        InputMsg::ReleaseAll => {
            totals.releases += 1;
            injector.release_all()
        }
        InputMsg::Held => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use rr_platform::input::{KeyCode, MouseButton};

    use super::*;

    /// Records calls, like the platform crate's test backend.
    #[derive(Clone, Default)]
    struct Recorder(Arc<StdMutex<Vec<String>>>);

    impl InputBackend for Recorder {
        fn key(&mut self, key: KeyCode, down: bool) -> Result<(), InputError> {
            self.0
                .lock()
                .unwrap()
                .push(format!("key {} {down}", key.name()));
            Ok(())
        }
        fn move_to(&mut self, x: u16, y: u16) -> Result<(), InputError> {
            self.0.lock().unwrap().push(format!("move {x} {y}"));
            Ok(())
        }
        fn button(&mut self, button: MouseButton, down: bool) -> Result<(), InputError> {
            self.0
                .lock()
                .unwrap()
                .push(format!("button {button:?} {down}"));
            Ok(())
        }
        fn wheel(&mut self, dx: i32, dy: i32) -> Result<(), InputError> {
            self.0.lock().unwrap().push(format!("wheel {dx} {dy}"));
            Ok(())
        }
        fn repeats_by_itself(&self) -> bool {
            false
        }
        fn name(&self) -> &'static str {
            "recorder"
        }
    }

    impl Recorder {
        fn calls(&self) -> Vec<String> {
            self.0.lock().unwrap().clone()
        }
    }

    fn moved(x: u16) -> InputMsg {
        InputMsg::MouseMove {
            monitor: 0,
            x,
            y: 0,
        }
    }

    #[test]
    fn moves_are_coalesced_but_keys_are_kept() {
        let queue = Queue::default();
        queue.push(moved(1));
        queue.push(moved(2));
        queue.push(InputMsg::Key {
            code: KeyCode::KeyA,
            down: true,
        });
        queue.push(moved(3));
        queue.push(InputMsg::Held);
        queue.push(moved(4));
        let mut batch = Vec::new();
        let (ended, last_seen) = queue.take(Duration::ZERO, &mut batch);
        assert!(!ended && last_seen.is_some());
        assert_eq!(
            batch,
            [
                moved(2),
                InputMsg::Key {
                    code: KeyCode::KeyA,
                    down: true
                },
                moved(4)
            ]
        );
        assert_eq!(queue.lock().coalesced, 2);
    }

    #[test]
    fn a_stuck_injector_gets_a_release_instead_of_a_backlog() {
        let queue = Queue::default();
        for down in [true, false].into_iter().cycle().take(MAX_QUEUED + 1) {
            queue.push(InputMsg::Key {
                code: KeyCode::KeyB,
                down,
            });
        }
        let mut batch = Vec::new();
        queue.take(Duration::ZERO, &mut batch);
        assert_eq!(batch, [InputMsg::ReleaseAll]);
        assert_eq!(queue.lock().overflows, 1);
    }

    #[test]
    fn the_watchdog_releases_held_keys_after_silence() {
        let recorder = Recorder::default();
        let queue = Arc::new(Queue::default());
        let thread = InputThread::start(Box::new(recorder.clone()), Arc::clone(&queue), 0).unwrap();
        queue.push(InputMsg::Key {
            code: KeyCode::ShiftLeft,
            down: true,
        });
        queue.push(InputMsg::MouseButton {
            button: MouseButton::Left,
            down: true,
        });
        // `Held` keeps it pressed past the watchdog period...
        let start = Instant::now();
        while start.elapsed() < WATCHDOG + WATCHDOG / 2 {
            queue.push(InputMsg::Held);
            std::thread::sleep(Duration::from_millis(250));
        }
        assert_eq!(recorder.calls(), ["key ShiftLeft true", "button Left true"]);
        // ...and silence releases it.
        std::thread::sleep(WATCHDOG + Duration::from_millis(400));
        assert_eq!(
            recorder.calls(),
            [
                "key ShiftLeft true",
                "button Left true",
                "button Left false",
                "key ShiftLeft false"
            ]
        );
        drop(thread);
    }

    #[test]
    fn the_end_of_input_releases_everything_and_skips_other_monitors() {
        let recorder = Recorder::default();
        let queue = Arc::new(Queue::default());
        let thread = InputThread::start(Box::new(recorder.clone()), Arc::clone(&queue), 1).unwrap();
        queue.push(InputMsg::MouseMove {
            monitor: 0,
            x: 5,
            y: 5,
        });
        queue.push(InputMsg::MouseMove {
            monitor: 1,
            x: 6,
            y: 7,
        });
        queue.push(InputMsg::Key {
            code: KeyCode::ControlLeft,
            down: true,
        });
        queue.push(InputMsg::Wheel { dx: 0, dy: 120 });
        drop(thread);
        assert_eq!(
            recorder.calls(),
            [
                "move 6 7",
                "key ControlLeft true",
                "wheel 0 120",
                "key ControlLeft false"
            ]
        );
    }
}
