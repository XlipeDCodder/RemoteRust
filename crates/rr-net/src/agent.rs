//! Agent side: accept connections, authenticate Viewers, run the control
//! session (blueprint v2 §5.3, §6.5, §7.3, §7.5).

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ipnet::IpNet;
use quinn::VarInt;
use rr_config::{KnownViewer, sanitize_device_name};
use rr_proto::{
    BoundedString, BoundedVec, CandidateAddr, ControlMsg, DevicePublicKey, DisconnectReason,
    Intent, MAX_DEVICE_NAME,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, timeout, timeout_at};

use crate::SessionError;
use crate::channel::{ControlChannel, disconnect_reason_for};
use crate::identity::{DeviceIdentity, Fingerprint};
use crate::pairing::{self, PairingCodes, PairingKeys, PairingUnavailable};
use crate::tls::{self, MAX_PENDING_HANDSHAKES, ViewerAccess};

/// TLS plus authentication must finish within this time (blueprint v2 §7.5).
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(5);

/// Application close code for an orderly end.
pub(crate) const CLOSE_NORMAL: VarInt = VarInt::from_u32(0);
/// Application close code after a refusal or error.
pub(crate) const CLOSE_REFUSED: VarInt = VarInt::from_u32(1);

/// How long a goodbye may take before the connection is closed anyway.
pub(crate) const GOODBYE_TIMEOUT: Duration = Duration::from_millis(500);

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
    server_config: quinn::ServerConfig,
    handshakes: Arc<Semaphore>,
    session: Arc<Semaphore>,
    addresses: RwLock<Vec<CandidateAddr>>,
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
                server_config,
                handshakes: Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES)),
                session: Arc::new(Semaphore::new(1)),
                addresses: RwLock::new(Vec::new()),
            }),
        })
    }

    /// The keys accepted by the TLS verifier; changes apply immediately.
    #[must_use]
    pub fn access(&self) -> &Arc<ViewerAccess> {
        &self.shared.access
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
        let deadline = Instant::now()
            .checked_add(AUTH_TIMEOUT)
            .ok_or(SessionError::Timeout)?;
        // The TLS verifier runs inside this await: unknown keys never get
        // past it while pairing is closed.
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

        let viewer = match timeout_at(deadline, self.authenticate(&conn, &mut ctl)).await {
            Ok(Ok(viewer)) => viewer,
            Ok(Err(err)) => return Err(refuse(&conn, &mut ctl, err).await),
            Err(elapsed) => return Err(refuse(&conn, &mut ctl, elapsed.into()).await),
        };

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

        let result = run_session(&mut ctl).await;
        match &result {
            Ok(()) => conn.close(CLOSE_NORMAL, b""),
            Err(err) => {
                let _ = timeout(GOODBYE_TIMEOUT, ctl.goodbye(disconnect_reason_for(err))).await;
                conn.close(CLOSE_REFUSED, b"");
            }
        }
        tracing::info!(viewer = %viewer.name, "session ended");
        result
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

/// Answers pings until the Viewer leaves.
async fn run_session(ctl: &mut ControlChannel) -> Result<(), SessionError> {
    loop {
        match ctl.recv().await {
            Ok(ControlMsg::Ping { t_us }) => ctl.send(&ControlMsg::Pong { t_us }).await?,
            Ok(ControlMsg::Pong { .. }) => {}
            Ok(ControlMsg::Disconnect { reason }) => {
                tracing::debug!(?reason, "viewer disconnected");
                return Ok(());
            }
            Ok(_) => return Err(SessionError::Protocol("unexpected control message")),
            Err(SessionError::Stream(_) | SessionError::Connection(_)) => return Ok(()),
            Err(err) => return Err(err),
        }
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
