//! Agent side: accept connections, authenticate Viewers, run the control
//! session (blueprint v2 §5.3, §6.5, §7.3, §7.5).

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ipnet::IpNet;
use quinn::VarInt;
use rr_config::{KnownViewer, sanitize_device_name};
use rr_proto::{
    BoundedString, BoundedVec, CandidateAddr, ControlMsg, DevicePublicKey, DisconnectReason,
    Intent, MAX_DEVICE_NAME, Permissions, StreamKind,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc, oneshot, watch};
use tokio::time::{Instant, timeout, timeout_at};

use crate::SessionError;
use crate::channel::{ControlChannel, ControlWriter, disconnect_reason_for};
use crate::cursor::CursorSender;
use crate::events::{AgentEvent, PeerInfo};
use crate::identity::{DeviceIdentity, Fingerprint};
use crate::input::InputReceiver;
use crate::limits::{FailureKind, FailureLimiter, LimitPolicy};
use crate::pairing::{self, PairingCodes, PairingKeys, PairingUnavailable};
use crate::session::{
    AgentSession, Answer, CONSENT_TIMEOUT, Command, Grant, SessionEvent, SessionHandle,
    SessionRequest,
};
use crate::streams::{self, Pending as PendingStream};
use crate::tls::{self, MAX_PENDING_HANDSHAKES, ViewerAccess};
use crate::video::VideoSender;

/// TLS plus authentication must finish within this time (blueprint v2 §7.5).
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(5);

/// Application close code for an orderly end.
pub(crate) const CLOSE_NORMAL: VarInt = VarInt::from_u32(0);
/// Application close code after a refusal or error.
pub(crate) const CLOSE_REFUSED: VarInt = VarInt::from_u32(1);

/// How long a goodbye may take before the connection is closed anyway.
pub(crate) const GOODBYE_TIMEOUT: Duration = Duration::from_millis(500);

/// Keyframe requests buffered for the media side; more are coalesced.
const EVENT_QUEUE: usize = 4;
/// Commands buffered from the media side.
const COMMAND_QUEUE: usize = 8;

/// Source addresses allowed to reach one listener. Packets from anywhere
/// else are dropped without an answer, before any TLS work.
#[derive(Debug, Clone)]
pub struct SourceFilter(Arc<[IpNet]>);

impl SourceFilter {
    /// Allows exactly the given networks (none = nobody).
    #[must_use]
    pub fn new(nets: impl IntoIterator<Item = IpNet>) -> Self {
        Self(nets.into_iter().map(|net| net.trunc()).collect())
    }

    /// Whether a packet from `ip` may proceed.
    #[must_use]
    pub fn allows(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.0.iter().any(|net| net.contains(&ip))
    }

    /// The allowed networks.
    #[must_use]
    pub fn networks(&self) -> &[IpNet] {
        &self.0
    }
}

/// How the Agent behaves.
#[derive(Debug)]
pub struct AgentOptions {
    /// Name shown to Viewers (sanitized before use).
    pub device_name: String,
    /// Session codes for attended pairing; `None` disables pairing, so
    /// unknown keys are rejected during the TLS handshake.
    pub pairing: Option<Arc<PairingCodes>>,
    /// Where newly paired Viewers are persisted; `None` keeps them in
    /// memory only.
    pub trust_path: Option<PathBuf>,
    /// Where screen-session requests go for the local user's consent;
    /// `None` refuses every request.
    pub sessions: Option<mpsc::Sender<SessionRequest>>,
    /// How long a request waits for an answer before it is denied
    /// ([`CONSENT_TIMEOUT`] unless testing).
    pub consent_timeout: Duration,
    /// Where events for the audit log and the local UI go; `None` drops
    /// them. They are sent with `try_send`: a full queue loses events
    /// (counted by [`Agent::dropped_events`]) rather than stalling
    /// connections.
    pub events: Option<mpsc::Sender<AgentEvent>>,
    /// Failure budgets ([`LimitPolicy::default`] unless testing).
    pub limits: LimitPolicy,
}

impl AgentOptions {
    /// Options with pairing off, nothing persisted and no sessions.
    #[must_use]
    pub fn new(device_name: impl Into<String>) -> Self {
        Self {
            device_name: device_name.into(),
            pairing: None,
            trust_path: None,
            sessions: None,
            consent_timeout: CONSENT_TIMEOUT,
            events: None,
            limits: LimitPolicy::default(),
        }
    }
}

/// A running Agent. Cheap to clone; all clones share state.
#[derive(Debug, Clone)]
pub struct Agent {
    shared: Arc<Shared>,
}

#[derive(Debug)]
struct Shared {
    identity: DeviceIdentity,
    device_name: BoundedString<MAX_DEVICE_NAME>,
    access: Arc<ViewerAccess>,
    pairing: Option<Arc<PairingCodes>>,
    trust_path: Option<PathBuf>,
    sessions: Option<mpsc::Sender<SessionRequest>>,
    consent_timeout: Duration,
    server_config: quinn::ServerConfig,
    handshakes: Arc<Semaphore>,
    session: Arc<Semaphore>,
    addresses: RwLock<Vec<CandidateAddr>>,
    events: Option<mpsc::Sender<AgentEvent>>,
    dropped_events: AtomicU64,
    limiter: Mutex<FailureLimiter>,
    /// Each send ends every connection with that reason.
    ends: watch::Sender<Option<DisconnectReason>>,
}

struct Authenticated {
    key: DevicePublicKey,
    name: String,
}

impl Agent {
    /// Creates an Agent that accepts the `known_viewers` keys.
    ///
    /// # Errors
    /// TLS configuration errors.
    pub fn new(
        identity: DeviceIdentity,
        options: AgentOptions,
        known_viewers: impl IntoIterator<Item = DevicePublicKey>,
    ) -> Result<Self, SessionError> {
        let access = Arc::new(ViewerAccess::new(known_viewers, options.pairing.is_some()));
        let server_config = tls::server_config(&identity, Arc::clone(&access))?;
        Ok(Self {
            shared: Arc::new(Shared {
                identity,
                device_name: BoundedString::truncating(&sanitize_device_name(&options.device_name)),
                access,
                pairing: options.pairing,
                trust_path: options.trust_path,
                sessions: options.sessions,
                consent_timeout: options.consent_timeout,
                server_config,
                handshakes: Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES)),
                session: Arc::new(Semaphore::new(1)),
                addresses: RwLock::new(Vec::new()),
                events: options.events,
                dropped_events: AtomicU64::new(0),
                limiter: Mutex::new(FailureLimiter::new(options.limits)),
                ends: watch::Sender::new(None),
            }),
        })
    }

    /// The keys accepted by the TLS verifier; changes apply immediately.
    #[must_use]
    pub fn access(&self) -> &Arc<ViewerAccess> {
        &self.shared.access
    }

    /// Ends every connection at once, telling each Viewer `reason`: the
    /// kill switch. A pending consent request is withdrawn; a running
    /// session's media side sees its events end.
    pub fn end_all(&self, reason: DisconnectReason) {
        self.shared.ends.send_replace(Some(reason));
    }

    /// Events lost because the event queue was full.
    #[must_use]
    pub fn dropped_events(&self) -> u64 {
        self.shared.dropped_events.load(Ordering::Relaxed)
    }

    /// Replaces the addresses announced to Viewers after authentication.
    pub fn set_addresses(&self, addrs: Vec<CandidateAddr>) {
        *self
            .shared
            .addresses
            .write()
            .unwrap_or_else(PoisonError::into_inner) = addrs;
    }

    /// Opens a QUIC listener on `addr` (never a wildcard address in
    /// production: see blueprint v2 §5.3).
    ///
    /// # Errors
    /// [`SessionError::Io`] if the socket cannot be bound.
    pub fn bind(&self, addr: SocketAddr) -> Result<quinn::Endpoint, SessionError> {
        Ok(quinn::Endpoint::server(
            self.shared.server_config.clone(),
            addr,
        )?)
    }

    /// Accepts connections on `endpoint` until it is closed.
    pub async fn serve(&self, endpoint: quinn::Endpoint, filter: SourceFilter) {
        while let Some(incoming) = endpoint.accept().await {
            let source = incoming.remote_address();
            if !filter.allows(source.ip()) {
                tracing::debug!(%source, "ignored a packet from outside the allowlist");
                incoming.ignore();
                continue;
            }
            let blocked = self
                .shared
                .limiter()
                .address_blocked(source.ip(), std::time::Instant::now());
            if let Some(blocked) = blocked {
                if blocked.first {
                    tracing::warn!(
                        %source,
                        remaining_ms = blocked.remaining.as_millis(),
                        "refusing an address after failed attempts"
                    );
                    self.shared.emit(AgentEvent::Blocked {
                        source: source.ip(),
                        remaining: blocked.remaining,
                    });
                }
                incoming.refuse();
                continue;
            }
            let Ok(permit) = Arc::clone(&self.shared.handshakes).try_acquire_owned() else {
                tracing::warn!(%source, "too many pending handshakes, refusing");
                incoming.refuse();
                continue;
            };
            let shared = Arc::clone(&self.shared);
            tokio::spawn(async move {
                if let Err(err) = shared.handle(incoming, permit).await {
                    tracing::info!(%source, error = %err, "connection ended with an error");
                }
            });
        }
    }
}

impl Shared {
    async fn handle(
        self: Arc<Self>,
        incoming: quinn::Incoming,
        handshake_permit: OwnedSemaphorePermit,
    ) -> Result<(), SessionError> {
        let source = incoming.remote_address();
        let (conn, mut ctl, viewer) = match self.admit(incoming).await {
            Ok(admitted) => admitted,
            Err(err) => {
                self.count_failure(source, &err);
                return Err(err);
            }
        };
        self.limiter().address_succeeded(source.ip());

        let Ok(_session) = Arc::clone(&self.session).try_acquire_owned() else {
            let err = SessionError::Refused(DisconnectReason::Busy);
            return Err(refuse(&conn, &mut ctl, err).await);
        };
        drop(handshake_permit);

        tracing::info!(
            viewer = %viewer.name,
            fingerprint = %Fingerprint::of(&viewer.key),
            remote = %conn.remote_address(),
            "session started"
        );
        let peer = PeerInfo::new(&viewer.name, &viewer.key);
        self.emit(AgentEvent::Connected {
            viewer: peer.clone(),
            source,
        });
        let connected_at = Instant::now();
        let addrs = self
            .addresses
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        ctl.send(&ControlMsg::SessionReady).await?;
        ctl.send(&ControlMsg::AgentAddresses {
            addrs: BoundedVec::truncating(addrs),
        })
        .await?;

        let (mut writer, reader) = ctl.split();
        let (incoming, reader_task) = reader.spawn();
        let mut ends = self.ends.subscribe();
        ends.mark_unchanged();
        let mut control = Control {
            shared: &self,
            conn: &conn,
            viewer: &viewer,
            writer: &mut writer,
            incoming,
            ends,
            state: State::Idle,
        };
        let result = control.run().await;
        drop(control);
        reader_task.abort();
        match &result {
            Ok(None) => conn.close(CLOSE_NORMAL, b""),
            Ok(Some(reason)) => {
                let _ = timeout(GOODBYE_TIMEOUT, writer.goodbye(*reason)).await;
                conn.close(CLOSE_NORMAL, b"");
            }
            Err(err) => {
                let _ = timeout(GOODBYE_TIMEOUT, writer.goodbye(disconnect_reason_for(err))).await;
                conn.close(CLOSE_REFUSED, b"");
            }
        }
        tracing::info!(viewer = %viewer.name, "session ended");
        let reason = match &result {
            Ok(reason) => *reason,
            Err(err) => Some(disconnect_reason_for(err)),
        };
        self.emit(AgentEvent::Disconnected {
            viewer: peer,
            reason,
            duration: connected_at.elapsed(),
        });
        result.map(|_| ())
    }

    /// TLS (whose verifier rejects unknown keys while pairing is closed),
    /// the control stream and authentication, all within [`AUTH_TIMEOUT`].
    async fn admit(
        &self,
        incoming: quinn::Incoming,
    ) -> Result<(quinn::Connection, ControlChannel, Authenticated), SessionError> {
        let deadline = Instant::now()
            .checked_add(AUTH_TIMEOUT)
            .ok_or(SessionError::Timeout)?;
        let conn = timeout_at(deadline, async { incoming.accept()?.await }).await??;
        let (send, recv) = match timeout_at(deadline, conn.accept_bi()).await {
            Ok(Ok(streams)) => streams,
            Ok(Err(err)) => return Err(err.into()),
            Err(elapsed) => {
                conn.close(CLOSE_REFUSED, b"timeout");
                return Err(elapsed.into());
            }
        };
        let mut ctl = ControlChannel::new(send, recv);
        match timeout_at(deadline, self.authenticate(&conn, &mut ctl)).await {
            Ok(Ok(viewer)) => Ok((conn, ctl, viewer)),
            Ok(Err(err)) => Err(refuse(&conn, &mut ctl, err).await),
            Err(elapsed) => Err(refuse(&conn, &mut ctl, elapsed.into()).await),
        }
    }

    /// Charges a failed attempt to its address (and the global budget), if
    /// it was one: a Viewer that simply went away is not a failure.
    fn count_failure(&self, source: SocketAddr, err: &SessionError) {
        let Some(kind) = failure_kind(err) else {
            return;
        };
        let now = std::time::Instant::now();
        let outcome = self.limiter().address_failed(source.ip(), now);
        tracing::warn!(
            %source,
            %kind,
            blocked_s = outcome.blocked_for.as_secs(),
            "connection attempt failed"
        );
        self.emit(AgentEvent::AuthFailed {
            source,
            kind,
            blocked_for: outcome.blocked_for,
        });
        if let Some(duration) = outcome.pairing_suspended_for {
            if let Some(until) = now.checked_add(duration) {
                self.access.suspend_pairing_until(until);
            }
            tracing::warn!(
                secs = duration.as_secs(),
                "too many failed attempts: pairing new devices is suspended"
            );
            self.emit(AgentEvent::PairingSuspended { duration });
        }
    }

    fn limiter(&self) -> MutexGuard<'_, FailureLimiter> {
        // Every limiter update completes before anything can panic, so
        // poisoning cannot leave it half updated.
        self.limiter.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn emit(&self, event: AgentEvent) {
        if let Some(events) = &self.events
            && events.try_send(event).is_err()
        {
            self.dropped_events.fetch_add(1, Ordering::Relaxed);
        }
    }

    async fn authenticate(
        &self,
        conn: &quinn::Connection,
        ctl: &mut ControlChannel,
    ) -> Result<Authenticated, SessionError> {
        tls::check_alpn(conn)?;
        let key = tls::connection_peer_key(conn)?;
        let ControlMsg::ViewerHello {
            device_name,
            intent,
        } = ctl.recv_active().await?
        else {
            return Err(SessionError::Protocol("expected ViewerHello"));
        };
        let name = sanitize_device_name(&device_name);
        let hello = ControlMsg::AgentHello {
            device_name: self.device_name.clone(),
        };

        match intent {
            Intent::Connect => {
                if !self.access.is_known(&key) {
                    return Err(SessionError::Refused(DisconnectReason::NotPaired));
                }
                ctl.send(&hello).await?;
            }
            Intent::Pair => {
                let codes = self
                    .pairing
                    .as_ref()
                    .filter(|_| self.access.pairing_open())
                    .ok_or(SessionError::Refused(DisconnectReason::PairingUnavailable))?;
                let attempt = codes.begin_attempt().map_err(|why| {
                    SessionError::Refused(match why {
                        PairingUnavailable::Busy => DisconnectReason::Busy,
                        PairingUnavailable::BackingOff => DisconnectReason::PairingUnavailable,
                    })
                })?;
                ctl.send(&hello).await?;
                let keys = PairingKeys {
                    viewer: key,
                    agent: self.identity.public_key(),
                };
                pairing::run_agent(ctl, conn, attempt, keys).await?;
                self.remember_viewer(key, &name).await;
                tracing::info!(
                    viewer = %name,
                    fingerprint = %Fingerprint::of(&key),
                    "paired with a new viewer"
                );
                self.emit(AgentEvent::Paired {
                    viewer: PeerInfo::new(&name, &key),
                    source: conn.remote_address(),
                });
            }
        }
        Ok(Authenticated { key, name })
    }

    /// Pins a newly paired Viewer and persists it if a trust file is set.
    async fn remember_viewer(&self, key: DevicePublicKey, name: &str) {
        self.access.add(key);
        let Some(path) = self.trust_path.clone() else {
            return;
        };
        let viewer = KnownViewer {
            name: name.to_owned(),
            key,
            paired_at: unix_now(),
        };
        // Re-read before writing: the Viewer role may have updated the same
        // file since this process started.
        let saved = tokio::task::spawn_blocking(move || {
            let mut store = rr_config::load_trust_or_default(&path)?;
            store.upsert_viewer(viewer)?;
            rr_config::save_trust(&path, &store)
        })
        .await;
        match saved {
            Ok(Ok(())) => {}
            Ok(Err(err)) => tracing::error!(error = %err, "could not save the paired viewer"),
            Err(err) => tracing::error!(error = %err, "could not save the paired viewer"),
        }
    }
}

/// Where the control loop stands with the (single) screen session a
/// connection may request.
enum State {
    /// No session requested yet.
    Idle,
    /// Waiting for the local user's answer.
    Asking {
        requested: Permissions,
        reply: oneshot::Receiver<Answer>,
        deadline: Instant,
    },
    /// Streaming.
    Active {
        events: mpsc::Sender<SessionEvent>,
        commands: mpsc::Receiver<Command>,
        /// Hands the Viewer's input stream to the media side: `Some` until
        /// it arrives, and only when `CONTROL` was granted.
        input: Option<oneshot::Sender<quinn::RecvStream>>,
    },
    /// The session ended; only pings and the goodbye remain.
    Done,
}

/// Outcome of one control-loop step.
enum Step {
    Continue,
    /// Leave the loop; `Some` sends a goodbye with this reason first.
    Stop(Option<DisconnectReason>),
}

/// The authenticated control session of one connection.
struct Control<'a> {
    shared: &'a Shared,
    conn: &'a quinn::Connection,
    viewer: &'a Authenticated,
    writer: &'a mut ControlWriter,
    incoming: mpsc::Receiver<Result<ControlMsg, SessionError>>,
    /// [`Agent::end_all`] requests.
    ends: watch::Receiver<Option<DisconnectReason>>,
    state: State,
}

impl Control<'_> {
    /// Runs until the Viewer leaves or the session ends. `Ok(Some(reason))`
    /// asks the caller to say goodbye with that reason.
    async fn run(&mut self) -> Result<Option<DisconnectReason>, SessionError> {
        loop {
            let step = tokio::select! {
                msg = self.incoming.recv() => self.on_message(msg).await?,
                stream = self.conn.accept_uni() => match stream {
                    Ok(stream) => self.on_stream(stream).await?,
                    // The connection is gone: the control stream says so too.
                    Err(_) => Step::Stop(None),
                },
                pending = next_pending(&mut self.state) => match pending {
                    Pending::Answer(answer) => self.on_answer(answer).await?,
                    Pending::Command(command) => self.on_command(command).await?,
                },
                changed = self.ends.changed() => {
                    // The sender lives in `Shared`, which outlives this loop.
                    let reason = changed
                        .ok()
                        .and_then(|()| *self.ends.borrow_and_update())
                        .unwrap_or(DisconnectReason::ShuttingDown);
                    tracing::info!(
                        viewer = %self.viewer.name,
                        ?reason,
                        "ending the connection on local request"
                    );
                    self.state = State::Done;
                    Step::Stop(Some(reason))
                }
            };
            if let Step::Stop(reason) = step {
                return Ok(reason);
            }
        }
    }

    async fn on_message(
        &mut self,
        msg: Option<Result<ControlMsg, SessionError>>,
    ) -> Result<Step, SessionError> {
        let msg = match msg {
            None | Some(Err(SessionError::Stream(_) | SessionError::Connection(_))) => {
                return Ok(Step::Stop(None));
            }
            Some(Err(err)) => return Err(err),
            Some(Ok(msg)) => msg,
        };
        match msg {
            ControlMsg::Ping { t_us } => self.writer.send(&ControlMsg::Pong { t_us }).await?,
            ControlMsg::Pong { .. } => {}
            ControlMsg::Disconnect { reason } => {
                tracing::debug!(?reason, "viewer disconnected");
                return Ok(Step::Stop(None));
            }
            ControlMsg::RequestSession { permissions } => {
                if !matches!(self.state, State::Idle) {
                    return Err(SessionError::Protocol("session already requested"));
                }
                self.ask(permissions).await?;
            }
            ControlMsg::RequestKeyframe => {
                if let State::Active { events, .. } = &self.state {
                    // A full queue already holds a request: coalesce.
                    let _ = events.try_send(SessionEvent::KeyframeRequested);
                }
            }
            _ => return Err(SessionError::Protocol("unexpected control message")),
        }
        Ok(Step::Continue)
    }

    /// A stream opened by the Viewer: only its input stream, once, in a
    /// session that granted `CONTROL`.
    async fn on_stream(&mut self, mut stream: quinn::RecvStream) -> Result<Step, SessionError> {
        let kind = streams::read_tag(&mut stream).await?;
        let State::Active { input, .. } = &mut self.state else {
            return Err(SessionError::Protocol("stream opened outside a session"));
        };
        let slot = input
            .take()
            .filter(|_| kind == StreamKind::Input)
            .ok_or(SessionError::Protocol("unexpected stream"))?;
        tracing::debug!(viewer = %self.viewer.name, "input stream open");
        // The media side may have stopped reading input: the stream is then
        // dropped, which stops it.
        let _ = slot.send(stream);
        Ok(Step::Continue)
    }

    /// Hands the request to the local user, or refuses at once if nobody
    /// can answer.
    async fn ask(&mut self, requested: Permissions) -> Result<(), SessionError> {
        let denied = SessionError::Refused(DisconnectReason::ConsentDenied);
        if !requested.contains(Permissions::VIEW) {
            return Err(denied);
        }
        let sessions = self.shared.sessions.as_ref().ok_or(denied)?;
        let blocked = self
            .shared
            .limiter()
            .key_blocked(&self.viewer.key, std::time::Instant::now());
        if let Some(blocked) = blocked {
            tracing::info!(
                viewer = %self.viewer.name,
                wait_ms = blocked.remaining.as_millis(),
                "session request refused: this device asked again too soon"
            );
            self.shared.emit(AgentEvent::SessionRefused {
                viewer: self.peer(),
                reason: DisconnectReason::RateLimited,
            });
            return Err(SessionError::Refused(DisconnectReason::RateLimited));
        }
        let (reply, receiver) = oneshot::channel();
        let request = SessionRequest {
            viewer_name: self.viewer.name.clone(),
            viewer_key: self.viewer.key,
            permissions: requested,
            reply,
        };
        sessions
            .try_send(request)
            .map_err(|_| SessionError::Refused(DisconnectReason::ConsentDenied))?;
        self.writer.send(&ControlMsg::ConsentPending).await?;
        let deadline = Instant::now()
            .checked_add(self.shared.consent_timeout)
            .ok_or(SessionError::Timeout)?;
        tracing::info!(viewer = %self.viewer.name, %requested, "session requested, asking the local user");
        self.shared.emit(AgentEvent::SessionRequested {
            viewer: self.peer(),
            permissions: requested,
        });
        self.state = State::Asking {
            requested,
            reply: receiver,
            deadline,
        };
        Ok(())
    }

    async fn on_answer(&mut self, answer: AnswerOutcome) -> Result<Step, SessionError> {
        let State::Asking { requested, .. } = self.state else {
            return Err(SessionError::Protocol("answer without a request"));
        };
        let (grant, reply) = match answer {
            AnswerOutcome::Answered(Answer::Accept { grant, session }) => (grant, session),
            AnswerOutcome::Answered(Answer::Deny) | AnswerOutcome::Dropped => {
                tracing::info!(viewer = %self.viewer.name, "session denied");
                return Err(self.refused(DisconnectReason::ConsentDenied));
            }
            AnswerOutcome::TimedOut => {
                tracing::info!(viewer = %self.viewer.name, "session request timed out");
                return Err(self.refused(DisconnectReason::ConsentTimeout));
            }
        };
        let permissions = grant.permissions.intersection(requested);
        if !permissions.contains(Permissions::VIEW) {
            let _ = reply.send(Err(SessionError::Refused(DisconnectReason::ConsentDenied)));
            return Err(self.refused(DisconnectReason::ConsentDenied));
        }
        match self.start(&grant, permissions).await {
            Ok((session, active)) => {
                tracing::info!(viewer = %self.viewer.name, %permissions, "session accepted");
                self.shared.limiter().key_accepted(&self.viewer.key);
                self.shared.emit(AgentEvent::SessionAccepted {
                    viewer: self.peer(),
                    permissions,
                });
                self.state = active;
                if reply.send(Ok(session)).is_err() {
                    // The media side is gone already: nothing to stream.
                    return Ok(Step::Stop(Some(DisconnectReason::MediaFailed)));
                }
                Ok(Step::Continue)
            }
            Err(err) => {
                let reason = disconnect_reason_for(&err);
                let _ = reply.send(Err(err));
                Err(SessionError::Refused(reason))
            }
        }
    }

    fn peer(&self) -> PeerInfo {
        PeerInfo::new(&self.viewer.name, &self.viewer.key)
    }

    /// A denied or unanswered request: the device waits before it may ask
    /// again (blueprint v2 §7.5).
    fn refused(&self, reason: DisconnectReason) -> SessionError {
        let wait = self
            .shared
            .limiter()
            .key_refused(self.viewer.key, std::time::Instant::now());
        tracing::debug!(viewer = %self.viewer.name, wait_s = wait.as_secs(), "next request delayed");
        self.shared.emit(AgentEvent::SessionRefused {
            viewer: self.peer(),
            reason,
        });
        SessionError::Refused(reason)
    }

    /// Sends `SessionStart` and the encoder name, then opens the video
    /// stream. The cursor stream opens with its first update, the input
    /// stream when the Viewer opens it.
    async fn start(
        &mut self,
        grant: &Grant,
        permissions: Permissions,
    ) -> Result<(AgentSession, State), SessionError> {
        let monitors = BoundedVec::new(grant.monitors.clone())
            .map_err(|_| SessionError::Protocol("too many monitors"))?;
        self.writer
            .send(&ControlMsg::SessionStart {
                permissions,
                monitors,
                monitor: grant.monitor,
            })
            .await?;
        self.writer
            .send(&ControlMsg::VideoEncoder {
                name: BoundedString::truncating(&grant.encoder),
            })
            .await?;
        let video = VideoSender::new(streams::open(self.conn, StreamKind::Video).await?);
        let (event_tx, event_rx) = mpsc::channel(EVENT_QUEUE);
        let (command_tx, command_rx) = mpsc::channel(COMMAND_QUEUE);
        let (input_tx, input) = if permissions.contains(Permissions::CONTROL) {
            let (tx, rx) = oneshot::channel();
            (
                Some(tx),
                Some(InputReceiver::new(PendingStream::Waiting(rx))),
            )
        } else {
            (None, None)
        };
        let session = AgentSession {
            video,
            cursor: Some(CursorSender::new(self.conn.clone())),
            input,
            events: event_rx,
            handle: SessionHandle {
                commands: command_tx,
            },
            permissions,
            viewer_name: self.viewer.name.clone(),
        };
        let state = State::Active {
            events: event_tx,
            commands: command_rx,
            input: input_tx,
        };
        Ok((session, state))
    }

    async fn on_command(&mut self, command: Option<Command>) -> Result<Step, SessionError> {
        match command {
            Some(Command::Encoder(name)) => {
                self.writer
                    .send(&ControlMsg::VideoEncoder {
                        name: BoundedString::truncating(&name),
                    })
                    .await?;
                Ok(Step::Continue)
            }
            Some(Command::Desktop(state)) => {
                self.writer
                    .send(&ControlMsg::DesktopState { state })
                    .await?;
                Ok(Step::Continue)
            }
            Some(Command::End(reason)) => {
                self.state = State::Done;
                Ok(Step::Stop(Some(reason)))
            }
            // Every handle was dropped: the media side stopped.
            None => {
                self.state = State::Done;
                Ok(Step::Stop(Some(DisconnectReason::Normal)))
            }
        }
    }
}

/// How the wait for the local user ended.
enum AnswerOutcome {
    Answered(Answer),
    /// The request was dropped without an answer.
    Dropped,
    TimedOut,
}

/// Session-side input to the control loop.
enum Pending {
    Answer(AnswerOutcome),
    Command(Option<Command>),
}

/// Resolves with the local user's answer while asking, or with the next
/// media-side command while streaming; never otherwise.
async fn next_pending(state: &mut State) -> Pending {
    match state {
        State::Asking {
            reply, deadline, ..
        } => Pending::Answer(match timeout_at(*deadline, reply).await {
            Ok(Ok(answer)) => AnswerOutcome::Answered(answer),
            Ok(Err(_)) => AnswerOutcome::Dropped,
            Err(_) => AnswerOutcome::TimedOut,
        }),
        State::Active { commands, .. } => Pending::Command(commands.recv().await),
        State::Idle | State::Done => std::future::pending().await,
    }
}

/// Whether a failed connection attempt counts against its address, and as
/// what. A Viewer that closed or lost its connection (for instance the
/// losing paths of its connection race) is not a failure.
fn failure_kind(err: &SessionError) -> Option<FailureKind> {
    match err {
        SessionError::Timeout | SessionError::Connection(quinn::ConnectionError::TimedOut) => {
            Some(FailureKind::Timeout)
        }
        // Locally detected: the TLS verifier refused the key, or the peer
        // broke the QUIC/TLS rules.
        SessionError::Connection(quinn::ConnectionError::TransportError(_)) => {
            Some(FailureKind::Handshake)
        }
        SessionError::PairingFailed | SessionError::Refused(DisconnectReason::PairingFailed) => {
            Some(FailureKind::WrongCode)
        }
        SessionError::Refused(DisconnectReason::NotPaired) => Some(FailureKind::NotPaired),
        SessionError::Refused(DisconnectReason::PairingUnavailable) => {
            Some(FailureKind::PairingUnavailable)
        }
        SessionError::Protocol(_) | SessionError::Frame(_) => Some(FailureKind::Protocol),
        _ => None,
    }
}

/// Tells the Viewer why it is refused, then closes the connection.
async fn refuse(
    conn: &quinn::Connection,
    ctl: &mut ControlChannel,
    err: SessionError,
) -> SessionError {
    let _ = timeout(GOODBYE_TIMEOUT, ctl.goodbye(disconnect_reason_for(&err))).await;
    conn.close(CLOSE_REFUSED, b"");
    err
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_filter_matches_networks() {
        let filter = SourceFilter::new([
            "100.64.0.0/10".parse().unwrap(),
            "fd7a:115c:a1e0::/48".parse().unwrap(),
        ]);
        assert!(filter.allows("100.101.102.103".parse().unwrap()));
        assert!(filter.allows("fd7a:115c:a1e0::1".parse().unwrap()));
        assert!(!filter.allows("192.168.1.10".parse().unwrap()));
        // IPv4-mapped IPv6 sources are matched as IPv4.
        assert!(filter.allows("::ffff:100.101.102.103".parse().unwrap()));
        assert!(!SourceFilter::new([]).allows("127.0.0.1".parse().unwrap()));
    }
}
