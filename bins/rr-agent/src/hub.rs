//! What the Agent's parts share: the consent request waiting for the local
//! user, the running session, recent failed attempts, the kill switch and
//! the audit log (blueprint v2 §7.3, §7.5, §7.6, §7.8).
//!
//! The network side, the media pipeline, the window and the tray all hold
//! one `Arc<Hub>`. Nothing here blocks for long: the kill switch runs on
//! the keyboard hook's thread, where the whole desktop's keyboard waits.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use rr_net::{Agent, AgentEvent, FailureKind, SessionHandle, SessionRequest};
use rr_proto::{DisconnectReason, Permissions};
use rr_telemetry::AuditLog;
use serde_json::{Value, json};

use crate::input::Queue;

/// Failed attempts kept for the window.
const RECENT_FAILURES: usize = 20;

/// How the kill switch was triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// The physical hotkey.
    Hotkey,
    /// The tray menu.
    Tray,
    /// The Agent window's button.
    Window,
    /// `stop` typed in the Agent's terminal.
    Console,
}

impl Via {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Hotkey => "hotkey",
            Self::Tray => "tray",
            Self::Window => "window",
            Self::Console => "console",
        }
    }
}

/// A screen request waiting for the local user.
pub struct Pending {
    /// The request itself; answered through [`Hub::answer`].
    request: SessionRequest,
    /// Who asks.
    pub viewer: String,
    /// The Viewer's fingerprint.
    pub fingerprint: String,
    /// What it asks for.
    pub permissions: Permissions,
    /// When it arrived.
    pub since: Instant,
    /// When it is denied automatically.
    pub deadline: Instant,
}

/// The session being shared.
pub struct Live {
    id: u64,
    /// The Viewer.
    pub viewer: String,
    /// Its fingerprint.
    pub fingerprint: String,
    /// What was granted.
    pub permissions: Permissions,
    /// When sharing started.
    pub started: Instant,
    handle: SessionHandle,
    input: Option<Arc<Queue>>,
    /// The secure desktop is showing (Windows).
    pub secure: bool,
}

/// A failed attempt, for the window.
#[derive(Debug, Clone)]
pub struct Failure {
    /// When.
    pub at: Instant,
    /// From where.
    pub source: IpAddr,
    /// What went wrong.
    pub kind: FailureKind,
    /// How long the address was then blocked.
    pub blocked_for: Duration,
}

/// The shared state; see [`Hub::state`].
#[derive(Default)]
pub struct State {
    /// The request waiting for an answer (at most one: the Agent serves
    /// one session at a time).
    pub pending: Option<Pending>,
    /// The session being shared.
    pub live: Option<Live>,
    /// The current session code and when it was drawn; `None` without
    /// pairing. Shown in the window only, never logged.
    pub code: Option<(String, Instant)>,
    /// Recent failed attempts, newest last.
    pub failures: VecDeque<Failure>,
    /// Failed attempts since the Agent started.
    pub failures_total: u64,
    /// Pairing new devices is suspended until then.
    pub pairing_suspended_until: Option<Instant>,
    /// Where the Agent listens, for the window.
    pub listening: Vec<String>,
    /// The kill switch fired then; cleared when the Viewer is gone.
    kill_started: Option<Instant>,
    next_live_id: u64,
}

/// See the module documentation.
pub struct Hub {
    agent: Agent,
    runtime: tokio::runtime::Handle,
    /// This device's name and fingerprint, for the window.
    pub device_name: String,
    /// See `device_name`.
    pub fingerprint: String,
    /// The kill-switch hotkey, when one is installed.
    hotkey: OnceLock<String>,
    /// Session-code lifetime, for the window.
    pub code_ttl: Duration,
    state: Mutex<State>,
    audit: Mutex<Option<AuditWriter>>,
    waker: OnceLock<Box<dyn Fn() + Send + Sync>>,
    /// Requests and session codes go to the terminal (no window).
    console: AtomicBool,
    /// Ctrl+C: the window should close and the Agent stop.
    quit: AtomicBool,
}

impl Hub {
    /// A hub for `agent`; audit records go to `audit_dir` (`None`: none).
    /// With `console`, requests and codes go to the terminal.
    pub fn new(
        agent: Agent,
        runtime: tokio::runtime::Handle,
        identity: (String, String),
        code_ttl: Duration,
        audit_dir: Option<&Path>,
        console: bool,
    ) -> Arc<Self> {
        let audit = audit_dir.and_then(start_audit);
        let (device_name, fingerprint) = identity;
        Arc::new(Self {
            agent,
            runtime,
            device_name,
            fingerprint,
            hotkey: OnceLock::new(),
            code_ttl,
            state: Mutex::new(State::default()),
            audit: Mutex::new(audit),
            waker: OnceLock::new(),
            console: AtomicBool::new(console),
            quit: AtomicBool::new(false),
        })
    }

    /// Whether requests and codes go to the terminal.
    pub fn console(&self) -> bool {
        self.console.load(Ordering::SeqCst)
    }

    /// The window could not open: requests and codes go to the terminal
    /// from now on (the current code is printed).
    pub fn use_console(&self) {
        self.console.store(true, Ordering::SeqCst);
        if let Some((code, _)) = &self.state().code {
            print_code(code, self.code_ttl);
        }
    }

    /// Asks the window to close (Ctrl+C in the terminal).
    pub fn request_quit(&self) {
        self.quit.store(true, Ordering::SeqCst);
        self.wake();
    }

    /// Whether [`Hub::request_quit`] was called.
    pub fn quit_requested(&self) -> bool {
        self.quit.load(Ordering::SeqCst)
    }

    /// The network side's runtime.
    pub fn runtime(&self) -> &tokio::runtime::Handle {
        &self.runtime
    }

    /// The shared state. Hold the guard briefly.
    pub fn state(&self) -> MutexGuard<'_, State> {
        // Every update is a few plain assignments: poisoning cannot leave
        // the state half updated.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Lets the window know something changed.
    pub fn set_waker(&self, wake: impl Fn() + Send + Sync + 'static) {
        let _ = self.waker.set(Box::new(wake));
    }

    fn wake(&self) {
        if let Some(wake) = self.waker.get() {
            wake();
        }
    }

    /// Records that the kill-switch hotkey is active.
    pub fn set_hotkey(&self, hotkey: String) {
        let _ = self.hotkey.set(hotkey);
    }

    /// The active kill-switch hotkey, if any.
    pub fn hotkey(&self) -> Option<&str> {
        self.hotkey.get().map(String::as_str)
    }

    /// Appends to the audit log (in the background).
    pub fn audit(&self, event: &str, fields: Value) {
        let audit = self.audit.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(audit) = &*audit {
            let _ = audit.records.send((event.to_owned(), fields));
        }
    }

    /// Writes what is still queued and closes the audit log; later records
    /// are dropped. Called once, at shutdown.
    pub fn close_audit(&self) {
        let audit = self
            .audit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(AuditWriter { records, thread }) = audit {
            // The writer stops once the channel is empty and closed.
            drop(records);
            if thread.join().is_err() {
                tracing::error!("the audit writer panicked");
            }
        }
    }

    // -- Consent ---------------------------------------------------------

    /// A new screen request for the window to show.
    pub fn offer(&self, request: SessionRequest, timeout: Duration) {
        let now = Instant::now();
        let pending = Pending {
            viewer: request.viewer_name().to_owned(),
            fingerprint: request.fingerprint().to_string(),
            permissions: request.permissions(),
            since: now,
            deadline: now.checked_add(timeout).unwrap_or(now),
            request,
        };
        let previous = self.state().pending.replace(pending);
        if let Some(previous) = previous {
            previous.request.deny();
        }
        self.wake();
    }

    /// Drops a request the Viewer withdrew (or that timed out); `true` if
    /// there was one.
    pub fn forget_withdrawn(&self) -> bool {
        let mut state = self.state();
        if state
            .pending
            .as_ref()
            .is_some_and(|pending| pending.request.is_withdrawn())
        {
            state.pending = None;
            return true;
        }
        false
    }

    /// The local user's answer to the pending request: `Some(permissions)`
    /// accepts with those, `None` denies.
    pub fn answer(self: &Arc<Self>, granted: Option<Permissions>) {
        let Some(pending) = self.state().pending.take() else {
            return;
        };
        match granted {
            Some(permissions) => {
                tracing::info!(viewer = %pending.viewer, %permissions, "accepted in the window");
                let hub = Arc::clone(self);
                self.runtime
                    .spawn(crate::consent::accept(pending.request, permissions, hub));
            }
            None => {
                tracing::info!(viewer = %pending.viewer, "denied in the window");
                pending.request.deny();
            }
        }
        self.wake();
    }

    // -- The running session ---------------------------------------------

    /// A session started; returns its id for the other `session_*` calls.
    pub fn session_started(
        &self,
        viewer: &str,
        fingerprint: String,
        permissions: Permissions,
        handle: SessionHandle,
        input: Option<Arc<Queue>>,
    ) -> u64 {
        let mut state = self.state();
        state.next_live_id = state.next_live_id.wrapping_add(1);
        let id = state.next_live_id;
        state.live = Some(Live {
            id,
            viewer: viewer.to_owned(),
            fingerprint,
            permissions,
            started: Instant::now(),
            handle,
            input,
            secure: false,
        });
        drop(state);
        self.wake();
        id
    }

    /// The secure desktop appeared (`true`) or went away.
    pub fn session_secure(&self, id: u64, secure: bool) {
        let viewer = {
            let mut state = self.state();
            let Some(live) = state.live.as_mut().filter(|live| live.id == id) else {
                return;
            };
            live.secure = secure;
            live.viewer.clone()
        };
        let what = if secure { "entered" } else { "left" };
        self.audit("secure_desktop", json!({ "state": what, "viewer": viewer }));
        self.wake();
    }

    /// The session is over.
    pub fn session_ended(&self, id: u64) {
        let mut state = self.state();
        if state.live.as_ref().is_some_and(|live| live.id == id) {
            state.live = None;
        }
        drop(state);
        self.wake();
    }

    // -- Kill switch -----------------------------------------------------

    /// Ends everything at once (blueprint v2 §7.6): injection stops before
    /// the next event, held keys are released, the Viewer is told
    /// `StoppedLocally`, a pending request is denied. Safe to call from the
    /// keyboard hook: it only flips flags and queues messages.
    pub fn kill(&self, via: Via) {
        let started = Instant::now();
        let (live, pending) = {
            let mut state = self.state();
            state.kill_started = Some(started);
            let live = state
                .live
                .as_ref()
                .map(|live| (live.viewer.clone(), live.handle.clone(), live.input.clone()));
            (live, state.pending.take())
        };
        if let Some((_, handle, input)) = &live {
            if let Some(queue) = input {
                queue.halt();
            }
            handle.end(DisconnectReason::StoppedLocally);
        }
        self.agent.end_all(DisconnectReason::StoppedLocally);
        if let Some(pending) = pending {
            pending.request.deny();
        }
        let viewer = live.map(|(viewer, ..)| viewer);
        tracing::warn!(via = via.as_str(), viewer = ?viewer, "kill switch: stopping all sessions");
        self.audit(
            "kill_switch",
            json!({ "via": via.as_str(), "viewer": viewer }),
        );
        self.wake();
    }

    /// Ends every connection because the Agent is quitting.
    pub fn shut_down(&self) {
        self.agent.end_all(DisconnectReason::ShuttingDown);
        if let Some(pending) = self.state().pending.take() {
            pending.request.deny();
        }
    }

    // -- Events from the network side --------------------------------------

    /// Records an event in the audit log and, for failures, in the window.
    pub fn on_event(&self, event: &AgentEvent) {
        let (name, fields) = audit_record(event);
        self.audit(name, fields);
        let now = Instant::now();
        let mut state = self.state();
        match event {
            AgentEvent::AuthFailed {
                source,
                kind,
                blocked_for,
            } => {
                state.failures_total = state.failures_total.saturating_add(1);
                if state.failures.len() >= RECENT_FAILURES {
                    state.failures.pop_front();
                }
                state.failures.push_back(Failure {
                    at: now,
                    source: source.ip(),
                    kind: *kind,
                    blocked_for: *blocked_for,
                });
            }
            AgentEvent::PairingSuspended { duration } => {
                state.pairing_suspended_until = now.checked_add(*duration);
            }
            AgentEvent::Disconnected { viewer, .. } => {
                if let Some(started) = state.kill_started.take() {
                    let elapsed = started.elapsed();
                    tracing::warn!(
                        viewer = %viewer.name,
                        elapsed_ms = elapsed.as_millis(),
                        "kill switch: viewer disconnected"
                    );
                }
            }
            _ => return,
        }
        drop(state);
        self.wake();
    }

    /// The session code changed (pairing on). It is shown to the local
    /// user only (window or terminal) and never logged.
    pub fn set_code(&self, code: String) {
        if self.console() {
            print_code(&code, self.code_ttl);
        }
        self.state().code = Some((code, Instant::now()));
        self.wake();
    }
}

/// Prints the session code for the local user (never logged).
fn print_code(code: &str, ttl: Duration) {
    let (head, tail) = code.split_at_checked(3).unwrap_or((code, ""));
    let minutes = ttl.as_secs().div_ceil(60);
    println!("  session code: {head} {tail}  (single use, valid for {minutes} min)");
}

/// The audit writer thread and the channel that feeds it.
struct AuditWriter {
    records: std::sync::mpsc::Sender<(String, Value)>,
    thread: std::thread::JoinHandle<()>,
}

/// Starts the audit writer thread; `None` (logged) if the file cannot be
/// opened.
fn start_audit(dir: &Path) -> Option<AuditWriter> {
    let mut log = match AuditLog::open(dir) {
        Ok(log) => log,
        Err(err) => {
            tracing::error!(error = %err, dir = %dir.display(), "cannot open the audit log");
            return None;
        }
    };
    tracing::info!(path = %log.path().display(), "audit log");
    let (tx, rx) = std::sync::mpsc::channel::<(String, Value)>();
    let spawned = std::thread::Builder::new()
        .name("rr-audit".to_owned())
        .spawn(move || {
            let mut failed = false;
            for (event, fields) in rx {
                if let Err(err) = log.record(&event, fields)
                    && !failed
                {
                    tracing::error!(error = %err, "cannot write the audit log");
                    failed = true;
                }
            }
        });
    match spawned {
        Ok(thread) => Some(AuditWriter {
            records: tx,
            thread,
        }),
        Err(err) => {
            tracing::error!(error = %err, "cannot start the audit writer");
            None
        }
    }
}

fn reason_name(reason: Option<DisconnectReason>) -> String {
    reason.map_or_else(|| "viewer_left".to_owned(), |reason| format!("{reason:?}"))
}

/// The audit record for a network event. No secrets: names, fingerprints,
/// addresses, permissions and reasons only.
pub fn audit_record(event: &AgentEvent) -> (&'static str, Value) {
    match event {
        AgentEvent::AuthFailed {
            source,
            kind,
            blocked_for,
        } => (
            "auth_failed",
            json!({ "source": source.to_string(), "kind": kind.as_str(), "blocked_s": blocked_for.as_secs() }),
        ),
        AgentEvent::Blocked { source, remaining } => (
            "address_blocked",
            json!({ "source": source.to_string(), "remaining_ms": u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX) }),
        ),
        AgentEvent::PairingSuspended { duration } => (
            "pairing_suspended",
            json!({ "duration_s": duration.as_secs() }),
        ),
        AgentEvent::Paired { viewer, source } => (
            "paired",
            json!({ "viewer": viewer.name, "fingerprint": viewer.fingerprint.to_string(), "source": source.to_string() }),
        ),
        AgentEvent::Connected { viewer, source } => (
            "connected",
            json!({ "viewer": viewer.name, "fingerprint": viewer.fingerprint.to_string(), "source": source.to_string() }),
        ),
        AgentEvent::SessionRequested {
            viewer,
            permissions,
        } => (
            "session_requested",
            json!({ "viewer": viewer.name, "fingerprint": viewer.fingerprint.to_string(), "permissions": permissions.to_string() }),
        ),
        AgentEvent::SessionAccepted {
            viewer,
            permissions,
        } => (
            "session_accepted",
            json!({ "viewer": viewer.name, "fingerprint": viewer.fingerprint.to_string(), "permissions": permissions.to_string() }),
        ),
        AgentEvent::SessionRefused { viewer, reason } => (
            "session_refused",
            json!({ "viewer": viewer.name, "fingerprint": viewer.fingerprint.to_string(), "reason": format!("{reason:?}") }),
        ),
        AgentEvent::Disconnected {
            viewer,
            reason,
            duration,
        } => (
            "disconnected",
            json!({
                "viewer": viewer.name,
                "fingerprint": viewer.fingerprint.to_string(),
                "reason": reason_name(*reason),
                "duration_s": duration.as_secs(),
            }),
        ),
        _ => ("event", json!({ "debug": format!("{event:?}") })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_records_name_the_event_and_hold_no_secrets() {
        let source = "100.64.1.2:50000".parse().unwrap();
        let (name, fields) = audit_record(&AgentEvent::AuthFailed {
            source,
            kind: FailureKind::WrongCode,
            blocked_for: Duration::from_secs(4),
        });
        assert_eq!(name, "auth_failed");
        assert_eq!(
            fields,
            json!({ "source": "100.64.1.2:50000", "kind": "wrong_code", "blocked_s": 4 })
        );
    }
}
