//! TLS 1.3 over QUIC with pinned device keys (blueprint v2 §6.1, §7.2).
//!
//! Certificates are only key containers: names, validity periods and
//! chains are ignored. A peer is accepted if and only if its Ed25519 key is
//! pinned, with one exception: while pairing is open, the Agent accepts
//! unknown Viewer keys *provisionally*, and the Viewer accepts any Agent key
//! when it asked to pair. Pairing then binds both keys into the SPAKE2
//! transcript, so a substituted key makes pairing fail.

use std::collections::HashSet;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::Duration;

use quinn::crypto::rustls::{HandshakeData, QuicClientConfig, QuicServerConfig};
use quinn::{IdleTimeout, TransportConfig, VarInt};
use rr_proto::{ALPN, DevicePublicKey};
use rustls::client::Resumption;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::NoServerSessionStorage;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::SingleCertAndKey;
use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme,
};

use crate::SessionError;
use crate::identity::{DeviceIdentity, Fingerprint, peer_public_key};

/// Keep-alive interval (blueprint v2 §6.1).
pub const KEEP_ALIVE: Duration = Duration::from_secs(2);

/// Idle timeout in milliseconds (blueprint v2 §6.1).
const IDLE_TIMEOUT_MS: u32 = 10_000;

/// Maximum QUIC handshakes waiting in the Agent's queue (blueprint v2 §7.5).
pub const MAX_PENDING_HANDSHAKES: usize = 8;

/// TLS exporter label for pairing channel binding (blueprint v2 §7.2).
pub(crate) const PAIRING_EXPORTER_LABEL: &[u8] = b"EXPORTER-rustremote-pairing";

/// The `ring` provider. TLS 1.3 only is enforced by every config builder.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Viewer keys the Agent accepts, shared with its TLS verifier so changes
/// apply to the next handshake.
#[derive(Debug, Default)]
pub struct ViewerAccess {
    state: RwLock<AccessState>,
}

#[derive(Debug, Default)]
struct AccessState {
    known: HashSet<DevicePublicKey>,
    pairing_open: bool,
}

impl ViewerAccess {
    /// Access list with the given pinned Viewer keys.
    #[must_use]
    pub fn new(known: impl IntoIterator<Item = DevicePublicKey>, pairing_open: bool) -> Self {
        Self {
            state: RwLock::new(AccessState {
                known: known.into_iter().collect(),
                pairing_open,
            }),
        }
    }

    /// Whether `key` is pinned.
    #[must_use]
    pub fn is_known(&self, key: &DevicePublicKey) -> bool {
        self.read(|state| state.known.contains(key))
    }

    /// Whether unknown keys may connect to pair.
    #[must_use]
    pub fn pairing_open(&self) -> bool {
        self.read(|state| state.pairing_open)
    }

    /// Opens or closes pairing for subsequent handshakes.
    pub fn set_pairing_open(&self, open: bool) {
        self.write(|state| state.pairing_open = open);
    }

    /// Pins `key`.
    pub fn add(&self, key: DevicePublicKey) {
        self.write(|state| {
            state.known.insert(key);
        });
    }

    /// Unpins `key`. Returns whether it was pinned.
    pub fn remove(&self, key: &DevicePublicKey) -> bool {
        self.write(|state| state.known.remove(key))
    }

    fn admits(&self, key: &DevicePublicKey) -> bool {
        self.read(|state| state.pairing_open || state.known.contains(key))
    }

    // A panic while holding the lock cannot leave `AccessState` half
    // updated (every write is a single set operation), so poisoning is
    // safe to ignore.
    fn read<T>(&self, f: impl FnOnce(&AccessState) -> T) -> T {
        f(&self.state.read().unwrap_or_else(PoisonError::into_inner))
    }

    fn write<T>(&self, f: impl FnOnce(&mut AccessState) -> T) -> T {
        f(&mut self.state.write().unwrap_or_else(PoisonError::into_inner))
    }
}

/// Which Agent keys the Viewer accepts on one connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AgentKeyPolicy {
    /// Only this pinned key.
    Pinned(DevicePublicKey),
    /// Any Ed25519 key; pairing must then succeed before anything else.
    Pairing,
}

/// Self-signed, single-certificate chains only; the key decides.
fn check_peer(
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    admit: impl FnOnce(&DevicePublicKey) -> bool,
    role: &'static str,
) -> Result<(), TlsError> {
    if !intermediates.is_empty() {
        return Err(TlsError::InvalidCertificate(CertificateError::BadEncoding));
    }
    let key = peer_public_key(end_entity)?;
    if admit(&key) {
        Ok(())
    } else {
        tracing::info!(
            peer = role,
            fingerprint = %Fingerprint::of(&key),
            "rejected an unknown device key during the TLS handshake"
        );
        Err(TlsError::InvalidCertificate(
            CertificateError::ApplicationVerificationFailure,
        ))
    }
}

fn verify_signature(
    provider: &CryptoProvider,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, TlsError> {
    rustls::crypto::verify_tls13_signature(
        message,
        cert,
        dss,
        &provider.signature_verification_algorithms,
    )
}

fn tls12_refused() -> TlsError {
    TlsError::General("TLS 1.2 is not supported".to_owned())
}

/// Viewer side: verifies the Agent's certificate.
#[derive(Debug)]
struct AgentCertVerifier {
    policy: AgentKeyPolicy,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AgentCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let admit = |key: &DevicePublicKey| match self.policy {
            AgentKeyPolicy::Pinned(expected) => *key == expected,
            AgentKeyPolicy::Pairing => true,
        };
        check_peer(end_entity, intermediates, admit, "agent")?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(tls12_refused())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_signature(&self.provider, message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// Agent side: verifies the Viewer's certificate.
#[derive(Debug)]
struct ViewerCertVerifier {
    access: Arc<ViewerAccess>,
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for ViewerCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        check_peer(
            end_entity,
            intermediates,
            |key| self.access.admits(key),
            "viewer",
        )?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(tls12_refused())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_signature(&self.provider, message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// QUIC transport parameters shared by both roles.
fn transport_config() -> Arc<TransportConfig> {
    let mut transport = TransportConfig::default();
    transport
        .keep_alive_interval(Some(KEEP_ALIVE))
        .max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(IDLE_TIMEOUT_MS))))
        // M1 only needs the control stream. Media streams (M2) raise these.
        .max_concurrent_bidi_streams(VarInt::from_u32(1))
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .datagram_receive_buffer_size(None);
    Arc::new(transport)
}

/// Agent (server) configuration: mutual TLS against `access`.
pub(crate) fn server_config(
    identity: &DeviceIdentity,
    access: Arc<ViewerAccess>,
) -> Result<quinn::ServerConfig, SessionError> {
    let provider = provider();
    let verifier = Arc::new(ViewerCertVerifier {
        access,
        provider: Arc::clone(&provider),
    });
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(identity.certified_key())));
    tls.alpn_protocols = vec![ALPN.to_vec()];
    // No resumption: every connection re-runs the verifier against the
    // current access list, and 0-RTT (replayable) is impossible.
    tls.send_tls13_tickets = 0;
    tls.session_storage = Arc::new(NoServerSessionStorage {});
    tls.max_early_data_size = 0;

    let crypto = QuicServerConfig::try_from(tls).map_err(|_| SessionError::NoInitialCipherSuite)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config
        .transport_config(transport_config())
        .max_incoming(MAX_PENDING_HANDSHAKES);
    Ok(config)
}

/// Viewer (client) configuration for one connection.
pub(crate) fn client_config(
    identity: &DeviceIdentity,
    policy: AgentKeyPolicy,
) -> Result<quinn::ClientConfig, SessionError> {
    let provider = provider();
    let verifier = Arc::new(AgentCertVerifier {
        policy,
        provider: Arc::clone(&provider),
    });
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(SingleCertAndKey::from(identity.certified_key())));
    tls.alpn_protocols = vec![ALPN.to_vec()];
    tls.resumption = Resumption::disabled();
    tls.enable_early_data = false;

    let crypto = QuicClientConfig::try_from(tls).map_err(|_| SessionError::NoInitialCipherSuite)?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(transport_config());
    Ok(config)
}

/// The peer's device key, as verified during the handshake.
pub(crate) fn connection_peer_key(
    conn: &quinn::Connection,
) -> Result<DevicePublicKey, SessionError> {
    let identity = conn
        .peer_identity()
        .ok_or(SessionError::Protocol("peer sent no certificate"))?;
    let chain = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| SessionError::Protocol("unexpected peer identity type"))?;
    let leaf = chain
        .first()
        .ok_or(SessionError::Protocol("peer sent no certificate"))?;
    Ok(peer_public_key(leaf)?)
}

/// Refuses connections that did not negotiate our ALPN. rustls already
/// enforces this for QUIC; checking again costs nothing.
pub(crate) fn check_alpn(conn: &quinn::Connection) -> Result<(), SessionError> {
    let negotiated = conn
        .handshake_data()
        .and_then(|data| data.downcast::<HandshakeData>().ok())
        .and_then(|data| data.protocol);
    if negotiated.as_deref() == Some(ALPN) {
        Ok(())
    } else {
        Err(SessionError::Protocol("ALPN mismatch"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_list_rules() {
        let known = DevicePublicKey([1; 32]);
        let stranger = DevicePublicKey([2; 32]);
        let access = ViewerAccess::new([known], false);
        assert!(access.admits(&known));
        assert!(!access.admits(&stranger));

        access.set_pairing_open(true);
        assert!(access.admits(&stranger));
        assert!(!access.is_known(&stranger));

        access.set_pairing_open(false);
        access.add(stranger);
        assert!(access.admits(&stranger));
        assert!(access.remove(&stranger));
        assert!(!access.admits(&stranger));
    }

    #[test]
    fn verifiers_check_the_pinned_key() {
        let agent = DeviceIdentity::generate().unwrap();
        let other = DeviceIdentity::generate().unwrap();
        let cert = agent.certified_key().cert[0].clone();
        let name = ServerName::try_from(crate::identity::CERT_SERVER_NAME).unwrap();

        let verify = |policy| {
            AgentCertVerifier {
                policy,
                provider: provider(),
            }
            .verify_server_cert(&cert, &[], &name, &[], UnixTime::now())
        };
        assert!(verify(AgentKeyPolicy::Pinned(agent.public_key())).is_ok());
        assert!(verify(AgentKeyPolicy::Pairing).is_ok());
        assert!(matches!(
            verify(AgentKeyPolicy::Pinned(other.public_key())),
            Err(TlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure
            ))
        ));

        let chain = [cert.clone()];
        let with_chain = AgentCertVerifier {
            policy: AgentKeyPolicy::Pairing,
            provider: provider(),
        }
        .verify_server_cert(&cert, &chain, &name, &[], UnixTime::now());
        assert!(with_chain.is_err(), "certificate chains are never accepted");
    }

    #[test]
    fn configs_build() {
        let identity = DeviceIdentity::generate().unwrap();
        let access = Arc::new(ViewerAccess::default());
        assert!(server_config(&identity, access).is_ok());
        assert!(client_config(&identity, AgentKeyPolicy::Pairing).is_ok());
    }
}
