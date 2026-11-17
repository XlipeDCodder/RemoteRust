//! Viewer side: pair with or connect to an Agent and run the control session
//! (blueprint v2 §5.4, §6.5, §7.3).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use rr_config::{KnownAgent, MAX_KNOWN_ADDRESSES, sanitize_device_name};
use rr_proto::{
    BoundedString, CandidateAddr, ControlMsg, DevicePublicKey, DisconnectReason, Intent,
    MAX_DEVICE_NAME, MonitorInfo, NetworkClass, Permissions,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::SessionError;
use crate::agent::{CLOSE_NORMAL, CLOSE_REFUSED, GOODBYE_TIMEOUT};
use crate::channel::{ControlChannel, ControlWriter, monotonic_us, rtt_since};
use crate::discovery;
use crate::identity::{CERT_SERVER_NAME, DeviceIdentity};
use crate::pairing::{self, PairingKeys, SessionCode};
use crate::race::{self, RaceError};
use crate::session::CONSENT_TIMEOUT;
use crate::tls::{self, AgentKeyPolicy};
use crate::video::VideoReceiver;

/// Limit for reaching an Agent and authenticating.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Limit for a `Pong` to come back.
pub const PING_TIMEOUT: Duration = Duration::from_secs(5);

/// Extra time, on top of the Agent's consent timeout, for its answer to
/// arrive.
const CONSENT_MARGIN: Duration = Duration::from_secs(5);

/// Commands buffered for the session's control task.
const COMMAND_QUEUE: usize = 8;
/// Events buffered for the application.
const EVENT_QUEUE: usize = 16;

/// This machine in the Viewer role.
#[derive(Debug, Clone)]
pub struct Viewer {
    identity: DeviceIdentity,
    device_name: BoundedString<MAX_DEVICE_NAME>,
}

impl Viewer {
    /// A Viewer presenting `identity` and `device_name` (sanitized).
    #[must_use]
    pub fn new(identity: DeviceIdentity, device_name: &str) -> Self {
        Self {
            identity,
            device_name: BoundedString::truncating(&sanitize_device_name(device_name)),
        }
    }

    /// This device's identity.
    #[must_use]
    pub const fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    /// First contact: accepts any Agent key, then proves knowledge of
    /// `code` with SPAKE2 bound to this TLS session. On success the caller
    /// should pin the Agent with [`ViewerSession::known_agent`].
    ///
    /// # Errors
    /// [`SessionError::PairingFailed`] for a wrong code, or any connection
    /// error.
    pub async fn pair(
        &self,
        addr: SocketAddr,
        code: &SessionCode,
    ) -> Result<ViewerSession, SessionError> {
        timeout(
            CONNECT_TIMEOUT,
            self.establish(addr, AgentKeyPolicy::Pairing, Some(code)),
        )
        .await?
    }

    /// Connects to an already paired Agent whose key must be `agent_key`.
    ///
    /// # Errors
    /// A TLS rejection ([`SessionError::is_tls_rejection`]) if either key
    /// is not the pinned one, or any connection error.
    pub async fn connect(
        &self,
        addr: SocketAddr,
        agent_key: DevicePublicKey,
    ) -> Result<ViewerSession, SessionError> {
        timeout(
            CONNECT_TIMEOUT,
            self.establish(addr, AgentKeyPolicy::Pinned(agent_key), None),
        )
        .await?
    }

    /// Connects to a paired Agent over the best available path: candidates
    /// are filtered by the VPNs up on this machine, ordered by `priority`
    /// and raced `stagger` apart (blueprint v2 §5.4).
    ///
    /// # Errors
    /// [`RaceError::NoCandidates`] or [`RaceError::AllFailed`].
    pub async fn connect_known(
        &self,
        agent: &KnownAgent,
        priority: &[NetworkClass],
        stagger: Duration,
    ) -> Result<ViewerSession, RaceError> {
        let interfaces = tokio::task::spawn_blocking(discovery::discover)
            .await
            .unwrap_or_default();
        let local = discovery::active_classes(&interfaces);
        let candidates = race::order_candidates(&agent.addresses, priority, &local);
        let key = agent.key;
        race::race(candidates, stagger, |candidate| {
            let viewer = self.clone();
            async move { viewer.connect(candidate.addr, key).await }
        })
        .await
        .map(|(_, session)| session)
    }

    async fn establish(
        &self,
        addr: SocketAddr,
        policy: AgentKeyPolicy,
        code: Option<&SessionCode>,
    ) -> Result<ViewerSession, SessionError> {
        let local: SocketAddr = if addr.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let endpoint = quinn::Endpoint::client(local)?;
        let config = tls::client_config(&self.identity, policy)?;
        let conn = endpoint
            .connect_with(config, addr, CERT_SERVER_NAME)?
            .await?;
        match self.authenticate(&conn, code).await {
            Ok((ctl, agent)) => Ok(ViewerSession {
                endpoint,
                conn,
                ctl,
                agent,
            }),
            Err(err) => {
                conn.close(CLOSE_REFUSED, b"");
                Err(err)
            }
        }
    }

    async fn authenticate(
        &self,
        conn: &quinn::Connection,
        code: Option<&SessionCode>,
    ) -> Result<(ControlChannel, AgentInfo), SessionError> {
        tls::check_alpn(conn)?;
        let agent_key = tls::connection_peer_key(conn)?;
        let (send, recv) = conn.open_bi().await?;
        let mut ctl = ControlChannel::new(send, recv);

        let intent = if code.is_some() {
            Intent::Pair
        } else {
            Intent::Connect
        };
        ctl.send(&ControlMsg::ViewerHello {
            device_name: self.device_name.clone(),
            intent,
        })
        .await?;
        let ControlMsg::AgentHello { device_name } = ctl.recv_active().await? else {
            return Err(SessionError::Protocol("expected AgentHello"));
        };
        if let Some(code) = code {
            let keys = PairingKeys {
                viewer: self.identity.public_key(),
                agent: agent_key,
            };
            pairing::run_viewer(&mut ctl, conn, code, keys).await?;
        }
        let ControlMsg::SessionReady = ctl.recv_active().await? else {
            return Err(SessionError::Protocol("expected SessionReady"));
        };
        let ControlMsg::AgentAddresses { addrs } = ctl.recv_active().await? else {
            return Err(SessionError::Protocol("expected AgentAddresses"));
        };
        Ok((
            ctl,
            AgentInfo {
                key: agent_key,
                name: sanitize_device_name(&device_name),
                addresses: addrs.into_inner(),
            },
        ))
    }
}

#[derive(Debug)]
struct AgentInfo {
    key: DevicePublicKey,
    name: String,
    addresses: Vec<CandidateAddr>,
}

/// An authenticated connection to an Agent.
#[derive(Debug)]
pub struct ViewerSession {
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    ctl: ControlChannel,
    agent: AgentInfo,
}

impl ViewerSession {
    /// The Agent's verified key.
    #[must_use]
    pub const fn agent_key(&self) -> DevicePublicKey {
        self.agent.key
    }

    /// The Agent's name (sanitized).
    #[must_use]
    pub fn agent_name(&self) -> &str {
        &self.agent.name
    }

    /// Addresses the Agent announced.
    #[must_use]
    pub fn agent_addresses(&self) -> &[CandidateAddr] {
        &self.agent.addresses
    }

    /// The address this session runs over.
    #[must_use]
    pub fn remote_address(&self) -> SocketAddr {
        self.conn.remote_address()
    }

    /// QUIC's own smoothed RTT estimate.
    #[must_use]
    pub fn quic_rtt(&self) -> Duration {
        self.conn.rtt()
    }

    /// Entry to pin in the trust store after pairing: the announced
    /// addresses, plus the one used now (as `manual`) if it was not announced.
    #[must_use]
    pub fn known_agent(&self, paired_at: u64) -> KnownAgent {
        let used = self.remote_address();
        let mut addresses = self.agent.addresses.clone();
        if !addresses.iter().any(|candidate| candidate.addr == used) {
            addresses.insert(
                0,
                CandidateAddr {
                    class: NetworkClass::Manual,
                    addr: used,
                },
            );
        }
        addresses.truncate(MAX_KNOWN_ADDRESSES);
        KnownAgent {
            name: self.agent.name.clone(),
            key: self.agent.key,
            addresses,
            paired_at,
        }
    }

    /// Measures the application-level round trip on the control stream.
    ///
    /// # Errors
    /// [`SessionError::Timeout`] or any stream error.
    pub async fn ping(&mut self) -> Result<Duration, SessionError> {
        let sent = monotonic_us();
        self.ctl.send(&ControlMsg::Ping { t_us: sent }).await?;
        timeout(PING_TIMEOUT, async {
            loop {
                match self.ctl.recv_active().await? {
                    ControlMsg::Pong { t_us } if t_us == sent => return Ok(rtt_since(sent)),
                    ControlMsg::Pong { .. } => {} // answer to an older ping
                    ControlMsg::Ping { t_us } => {
                        self.ctl.send(&ControlMsg::Pong { t_us }).await?;
                    }
                    _ => return Err(SessionError::Protocol("unexpected control message")),
                }
            }
        })
        .await?
    }

    /// Ends the session politely and waits briefly for the close to be sent.
    pub async fn close(mut self) {
        let _ = timeout(GOODBYE_TIMEOUT, self.ctl.goodbye(DisconnectReason::Normal)).await;
        self.conn.close(CLOSE_NORMAL, b"");
        let _ = timeout(Duration::from_secs(1), self.endpoint.wait_idle()).await;
    }

    /// Asks for a screen session. The Agent's local user must accept, so
    /// this can take up to the consent timeout (30 s) plus a margin.
    ///
    /// # Errors
    /// [`SessionError::Closed`] with `ConsentDenied` / `ConsentTimeout`
    /// when refused, [`SessionError::Timeout`], or any stream error.
    pub async fn start(mut self, permissions: Permissions) -> Result<RemoteSession, SessionError> {
        let result = timeout(
            CONSENT_TIMEOUT.saturating_add(CONSENT_MARGIN),
            self.request(permissions),
        )
        .await
        .map_err(SessionError::from)
        .and_then(|inner| inner);
        let grant = match result {
            Ok(grant) => grant,
            Err(err) => {
                if !matches!(err, SessionError::Closed(_)) {
                    let _ =
                        timeout(GOODBYE_TIMEOUT, self.ctl.goodbye(DisconnectReason::Normal)).await;
                }
                self.conn.close(CLOSE_REFUSED, b"");
                return Err(err);
            }
        };
        let video = VideoReceiver::new(self.conn.clone());
        let (writer, reader) = self.ctl.split();
        let (incoming, reader_task) = reader.spawn();
        let (command_tx, command_rx) = mpsc::channel(COMMAND_QUEUE);
        let (event_tx, event_rx) = mpsc::channel(EVENT_QUEUE);
        let control = tokio::spawn(run_control(writer, incoming, command_rx, event_tx));
        Ok(RemoteSession {
            endpoint: self.endpoint,
            conn: self.conn,
            agent: self.agent,
            grant,
            video: Some(video),
            events: Some(event_rx),
            commands: SessionControl {
                commands: command_tx,
            },
            tasks: [control, reader_task],
        })
    }

    async fn request(&mut self, permissions: Permissions) -> Result<SessionGrant, SessionError> {
        self.ctl
            .send(&ControlMsg::RequestSession { permissions })
            .await?;
        loop {
            match self.ctl.recv_active().await? {
                ControlMsg::ConsentPending | ControlMsg::Pong { .. } => {}
                ControlMsg::Ping { t_us } => self.ctl.send(&ControlMsg::Pong { t_us }).await?,
                ControlMsg::SessionStart {
                    permissions: granted,
                    monitors,
                    monitor,
                } => {
                    if !permissions.contains(granted) || !granted.contains(Permissions::VIEW) {
                        return Err(SessionError::Protocol("unexpected permissions granted"));
                    }
                    let monitors = monitors.into_inner();
                    if !monitors.iter().any(|candidate| candidate.id == monitor) {
                        return Err(SessionError::Protocol("unknown monitor"));
                    }
                    return Ok(SessionGrant {
                        permissions: granted,
                        monitors,
                        monitor,
                    });
                }
                _ => return Err(SessionError::Protocol("unexpected control message")),
            }
        }
    }
}

/// What the Agent granted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionGrant {
    /// Granted permissions.
    pub permissions: Permissions,
    /// The Agent's monitors.
    pub monitors: Vec<MonitorInfo>,
    /// The monitor being streamed.
    pub monitor: u8,
}

/// Something the Agent said during a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteEvent {
    /// The Agent now encodes with this encoder.
    Encoder(String),
    /// The session is over; `Some` carries the Agent's reason.
    Ended(Option<DisconnectReason>),
}

/// Cheap, cloneable control over a [`RemoteSession`], usable from any
/// thread.
#[derive(Debug, Clone)]
pub struct SessionControl {
    commands: mpsc::Sender<ViewerCommand>,
}

#[derive(Debug)]
enum ViewerCommand {
    RequestKeyframe,
    Close,
}

impl SessionControl {
    /// Asks the Agent for a keyframe (after a decode error). Requests made
    /// while one is still queued are coalesced.
    pub fn request_keyframe(&self) {
        let _ = self.commands.try_send(ViewerCommand::RequestKeyframe);
    }

    /// Ends the session.
    pub fn close(&self) {
        let _ = self.commands.try_send(ViewerCommand::Close);
    }
}

/// Path statistics for the overlay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathStats {
    /// QUIC's smoothed RTT estimate.
    pub rtt: Duration,
    /// Packets sent so far.
    pub sent_packets: u64,
    /// Packets declared lost so far.
    pub lost_packets: u64,
}

/// A running screen session on the Viewer.
#[derive(Debug)]
pub struct RemoteSession {
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    agent: AgentInfo,
    grant: SessionGrant,
    video: Option<VideoReceiver>,
    events: Option<mpsc::Receiver<RemoteEvent>>,
    commands: SessionControl,
    tasks: [JoinHandle<()>; 2],
}

impl RemoteSession {
    /// What the Agent granted.
    #[must_use]
    pub const fn grant(&self) -> &SessionGrant {
        &self.grant
    }

    /// The Agent's name (sanitized).
    #[must_use]
    pub fn agent_name(&self) -> &str {
        &self.agent.name
    }

    /// The address this session runs over.
    #[must_use]
    pub fn remote_address(&self) -> SocketAddr {
        self.conn.remote_address()
    }

    /// The video stream; `None` after the first call.
    pub fn take_video(&mut self) -> Option<VideoReceiver> {
        self.video.take()
    }

    /// Agent events; `None` after the first call.
    pub fn take_events(&mut self) -> Option<mpsc::Receiver<RemoteEvent>> {
        self.events.take()
    }

    /// A control handle.
    #[must_use]
    pub fn control(&self) -> SessionControl {
        self.commands.clone()
    }

    /// Current path statistics.
    #[must_use]
    pub fn path_stats(&self) -> PathStats {
        self.stats_source().path_stats()
    }

    /// A cheap handle to read path statistics from another task.
    #[must_use]
    pub fn stats_source(&self) -> StatsSource {
        StatsSource {
            conn: self.conn.clone(),
        }
    }

    /// Ends the session politely and waits briefly for the close to be sent.
    pub async fn close(self) {
        self.commands.close();
        let [control, reader] = self.tasks;
        let _ = timeout(GOODBYE_TIMEOUT.saturating_add(GOODBYE_TIMEOUT), control).await;
        reader.abort();
        self.conn.close(CLOSE_NORMAL, b"");
        let _ = timeout(Duration::from_secs(1), self.endpoint.wait_idle()).await;
    }
}

/// Reads path statistics of a session from anywhere.
#[derive(Debug, Clone)]
pub struct StatsSource {
    conn: quinn::Connection,
}

impl StatsSource {
    /// Current path statistics.
    #[must_use]
    pub fn path_stats(&self) -> PathStats {
        let stats = self.conn.stats();
        PathStats {
            rtt: self.conn.rtt(),
            sent_packets: stats.path.sent_packets,
            lost_packets: stats.path.lost_packets,
        }
    }
}

/// The Viewer's control loop during a session.
async fn run_control(
    mut writer: ControlWriter,
    mut incoming: mpsc::Receiver<Result<ControlMsg, SessionError>>,
    mut commands: mpsc::Receiver<ViewerCommand>,
    events: mpsc::Sender<RemoteEvent>,
) {
    let ended = loop {
        tokio::select! {
            msg = incoming.recv() => match msg {
                Some(Ok(ControlMsg::VideoEncoder { name })) => {
                    let name = sanitize_device_name(&name);
                    let _ = events.send(RemoteEvent::Encoder(name)).await;
                }
                Some(Ok(ControlMsg::Ping { t_us })) => {
                    if writer.send(&ControlMsg::Pong { t_us }).await.is_err() {
                        break None;
                    }
                }
                Some(Ok(ControlMsg::Pong { .. })) => {}
                Some(Ok(ControlMsg::Disconnect { reason })) => break Some(reason),
                Some(Ok(_)) => {
                    let _ = timeout(GOODBYE_TIMEOUT, writer.goodbye(DisconnectReason::ProtocolError)).await;
                    break None;
                }
                Some(Err(err)) => {
                    tracing::debug!(error = %err, "control stream ended");
                    break None;
                }
                None => break None,
            },
            command = commands.recv() => match command {
                Some(ViewerCommand::RequestKeyframe) => {
                    if writer.send(&ControlMsg::RequestKeyframe).await.is_err() {
                        break None;
                    }
                }
                Some(ViewerCommand::Close) | None => {
                    let _ = timeout(GOODBYE_TIMEOUT, writer.goodbye(DisconnectReason::Normal)).await;
                    break None;
                }
            },
        }
    };
    let _ = events.send(RemoteEvent::Ended(ended)).await;
}
