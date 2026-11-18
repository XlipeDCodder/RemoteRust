//! End-to-end tests over loopback: real QUIC, real TLS, real SPAKE2.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rr_net::{
    Agent, AgentOptions, CodePolicy, DeviceIdentity, LimitPolicy, PairingCodes, SessionCode,
    SessionError, SourceFilter, Viewer,
};
use rr_proto::{DevicePublicKey, DisconnectReason};

struct TestAgent {
    agent: Agent,
    key: DevicePublicKey,
    addr: SocketAddr,
    codes: Option<Arc<PairingCodes>>,
    endpoint: quinn::Endpoint,
}

impl TestAgent {
    fn code(&self) -> SessionCode {
        self.codes.as_ref().unwrap().subscribe().borrow().clone()
    }
}

impl Drop for TestAgent {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"");
    }
}

fn test_policy() -> CodePolicy {
    CodePolicy {
        ttl: Duration::from_secs(300),
        max_attempts: 3,
        backoff_base: Duration::ZERO,
        backoff_max: Duration::ZERO,
    }
}

/// An Agent without failure budgets: these tests repeat failures from one
/// address on purpose (see `wrong_code_blocks_the_address_briefly`).
fn start_agent_with(
    pairing: bool,
    known: &[DevicePublicKey],
    filter: SourceFilter,
    trust_path: Option<std::path::PathBuf>,
) -> TestAgent {
    start_agent_limited(pairing, known, filter, trust_path, LimitPolicy::disabled())
}

fn start_agent_limited(
    pairing: bool,
    known: &[DevicePublicKey],
    filter: SourceFilter,
    trust_path: Option<std::path::PathBuf>,
    limits: LimitPolicy,
) -> TestAgent {
    let identity = DeviceIdentity::generate().unwrap();
    let key = identity.public_key();
    let codes = pairing.then(|| PairingCodes::new(test_policy()).unwrap());
    let options = AgentOptions {
        pairing: codes.clone(),
        trust_path,
        limits,
        ..AgentOptions::new("test-agent")
    };
    let agent = Agent::new(identity, options, known.iter().copied()).unwrap();
    let endpoint = agent.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn({
        let agent = agent.clone();
        let endpoint = endpoint.clone();
        async move { agent.serve(endpoint, filter).await }
    });
    TestAgent {
        agent,
        key,
        addr,
        codes,
        endpoint,
    }
}

fn loopback_only() -> SourceFilter {
    SourceFilter::new(["127.0.0.0/8".parse().unwrap()])
}

fn start_agent(pairing: bool, known: &[DevicePublicKey]) -> TestAgent {
    start_agent_with(pairing, known, loopback_only(), None)
}

fn new_viewer(name: &str) -> Viewer {
    Viewer::new(DeviceIdentity::generate().unwrap(), name)
}

fn wrong_code(right: &SessionCode) -> SessionCode {
    let mut text = right.expose().to_owned();
    let first = text.remove(0);
    text.insert(0, if first == '0' { '1' } else { '0' });
    SessionCode::parse(&text).unwrap()
}

#[tokio::test]
async fn pairing_pins_both_sides_then_connect_works() {
    let agent = start_agent(true, &[]);
    let viewer = new_viewer("test-viewer");
    let viewer_key = viewer.identity().public_key();

    let mut session = viewer.pair(agent.addr, &agent.code()).await.unwrap();
    assert_eq!(session.agent_key(), agent.key);
    assert_eq!(session.agent_name(), "test-agent");
    assert!(agent.agent.access().is_known(&viewer_key));
    let rtt = session.ping().await.unwrap();
    assert!(rtt < Duration::from_secs(1));
    let pinned = session.known_agent(1);
    assert_eq!(pinned.key, agent.key);
    assert_eq!(pinned.addresses[0].addr, agent.addr);
    session.close().await;

    // Second contact: pinned keys, no code.
    let mut session = viewer.connect(agent.addr, agent.key).await.unwrap();
    session.ping().await.unwrap();
    session.close().await;
}

#[tokio::test]
async fn a_used_code_cannot_be_reused() {
    let agent = start_agent(true, &[]);
    let code = agent.code();
    new_viewer("first")
        .pair(agent.addr, &code)
        .await
        .unwrap()
        .close()
        .await;
    assert_ne!(agent.code(), code, "codes are single-use");

    let err = new_viewer("second")
        .pair(agent.addr, &code)
        .await
        .unwrap_err();
    assert!(matches!(err, SessionError::PairingFailed), "{err:?}");
}

#[tokio::test]
async fn three_wrong_codes_rotate_the_code() {
    let agent = start_agent(true, &[]);
    let original = agent.code();
    let viewer = new_viewer("guesser");

    for attempt in 1..=3 {
        let err = viewer
            .pair(agent.addr, &wrong_code(&original))
            .await
            .unwrap_err();
        assert!(matches!(err, SessionError::PairingFailed), "{err:?}");
        if attempt < 3 {
            assert_eq!(agent.code(), original, "rotated too early");
        }
    }
    let rotated = agent.code();
    assert_ne!(rotated, original, "third failure must rotate the code");
    assert!(
        !agent
            .agent
            .access()
            .is_known(&viewer.identity().public_key())
    );

    // The old code is dead, the new one works.
    let err = viewer.pair(agent.addr, &original).await.unwrap_err();
    assert!(matches!(err, SessionError::PairingFailed), "{err:?}");
    viewer
        .pair(agent.addr, &rotated)
        .await
        .unwrap()
        .close()
        .await;
}

#[tokio::test]
async fn unknown_key_is_rejected_in_the_tls_handshake() {
    let agent = start_agent(false, &[]);
    let err = new_viewer("stranger")
        .connect(agent.addr, agent.key)
        .await
        .unwrap_err();
    assert!(err.is_tls_rejection(), "{err:?}");
}

#[tokio::test]
async fn closing_pairing_at_runtime_takes_effect() {
    let agent = start_agent(true, &[]);
    agent.agent.access().set_pairing_open(false);
    let err = new_viewer("late")
        .pair(agent.addr, &agent.code())
        .await
        .unwrap_err();
    assert!(err.is_tls_rejection(), "{err:?}");
}

#[tokio::test]
async fn viewer_rejects_an_agent_with_another_key() {
    let viewer = new_viewer("careful");
    let agent = start_agent(false, &[viewer.identity().public_key()]);
    let impostor_key = DeviceIdentity::generate().unwrap().public_key();
    let err = viewer.connect(agent.addr, impostor_key).await.unwrap_err();
    assert!(err.is_tls_rejection(), "{err:?}");
    // The genuine key still works.
    viewer
        .connect(agent.addr, agent.key)
        .await
        .unwrap()
        .close()
        .await;
}

#[tokio::test]
async fn connect_without_pairing_is_refused() {
    let agent = start_agent(true, &[]);
    let err = new_viewer("impatient")
        .connect(agent.addr, agent.key)
        .await
        .unwrap_err();
    assert!(
        matches!(err, SessionError::Closed(DisconnectReason::NotPaired)),
        "{err:?}"
    );
}

#[tokio::test]
async fn only_one_session_at_a_time() {
    let first = new_viewer("first");
    let second = new_viewer("second");
    let agent = start_agent(
        false,
        &[
            first.identity().public_key(),
            second.identity().public_key(),
        ],
    );
    let session = first.connect(agent.addr, agent.key).await.unwrap();
    let err = second.connect(agent.addr, agent.key).await.unwrap_err();
    assert!(
        matches!(err, SessionError::Closed(DisconnectReason::Busy)),
        "{err:?}"
    );
    session.close().await;
    // The slot frees up once the Agent has processed the goodbye.
    for retry in 0.. {
        match second.connect(agent.addr, agent.key).await {
            Ok(session) => return session.close().await,
            Err(SessionError::Closed(DisconnectReason::Busy)) if retry < 40 => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(err) => panic!("{err:?}"),
        }
    }
}

#[tokio::test]
async fn sources_outside_the_allowlist_get_no_answer() {
    let viewer = new_viewer("outsider");
    let agent = start_agent_with(
        false,
        &[viewer.identity().public_key()],
        SourceFilter::new(["10.0.0.0/8".parse().unwrap()]),
        None,
    );
    let attempt = tokio::time::timeout(
        Duration::from_secs(1),
        viewer.connect(agent.addr, agent.key),
    )
    .await;
    assert!(attempt.is_err(), "the Agent must stay silent: {attempt:?}");
}

#[tokio::test]
async fn paired_viewer_is_persisted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(rr_config::TRUST_FILE_NAME);
    let agent = start_agent_with(true, &[], loopback_only(), Some(path.clone()));
    let viewer = new_viewer("remembered");
    viewer
        .pair(agent.addr, &agent.code())
        .await
        .unwrap()
        .close()
        .await;

    let store = rr_config::load_trust(&path).unwrap();
    let entry = store.viewer(&viewer.identity().public_key()).unwrap();
    assert_eq!(entry.name, "remembered");
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
async fn listener_set_announces_addresses_and_the_race_finds_a_path() {
    use rr_net::ListenerSet;
    use rr_net::listen::loopback_target;
    use rr_proto::{CandidateAddr, NetworkClass};

    let identity = DeviceIdentity::generate().unwrap();
    let agent_key = identity.public_key();
    let codes = PairingCodes::new(test_policy()).unwrap();
    let agent = Agent::new(
        identity,
        AgentOptions {
            pairing: Some(Arc::clone(&codes)),
            ..AgentOptions::new("listener-agent")
        },
        [],
    )
    .unwrap();
    let target = loopback_target(free_udp_port());
    let mut listeners = ListenerSet::new(agent.clone());
    listeners.apply(std::slice::from_ref(&target));
    assert_eq!(listeners.targets().count(), 1);

    // Pairing teaches the Viewer the announced addresses.
    let viewer = new_viewer("racer");
    let code = codes.subscribe().borrow().clone();
    let session = viewer.pair(target.addr, &code).await.unwrap();
    assert_eq!(
        session.agent_addresses(),
        [CandidateAddr {
            class: NetworkClass::Manual,
            addr: target.addr
        }]
    );
    let mut known = session.known_agent(1);
    session.close().await;

    // A dead address and an impostor come first; the race still connects.
    let impostor = start_agent(false, &[]);
    known.addresses.insert(
        0,
        CandidateAddr {
            class: NetworkClass::Manual,
            addr: impostor.addr,
        },
    );
    known.addresses.insert(
        0,
        CandidateAddr {
            class: NetworkClass::Manual,
            addr: format!("127.0.0.1:{}", free_udp_port()).parse().unwrap(),
        },
    );
    let started = std::time::Instant::now();
    let session = viewer
        .connect_known(&known, &NetworkClass::ALL, Duration::from_millis(50))
        .await
        .unwrap();
    assert_eq!(session.agent_key(), agent_key);
    assert_eq!(session.remote_address(), target.addr);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    session.close().await;

    // Removing the listener stops answering.
    listeners.close_all();
    assert_eq!(listeners.targets().count(), 0);
    let gone = tokio::time::timeout(
        Duration::from_secs(1),
        viewer.connect(target.addr, agent_key),
    )
    .await;
    assert!(
        !matches!(gone, Ok(Ok(_))),
        "closed listener must not accept"
    );
}

#[tokio::test]
async fn race_without_candidates_fails_fast() {
    use rr_config::KnownAgent;
    use rr_proto::{CandidateAddr, NetworkClass};

    let viewer = new_viewer("lonely");
    let known = KnownAgent {
        name: "remote".to_owned(),
        key: DevicePublicKey([5; 32]),
        // Radmin is only tried when a local Radmin adapter is up.
        addresses: vec![CandidateAddr {
            class: NetworkClass::Radmin,
            addr: "26.1.2.3:7878".parse().unwrap(),
        }],
        paired_at: 0,
    };
    let err = viewer
        .connect_known(&known, &[NetworkClass::Tailscale], Duration::ZERO)
        .await
        .unwrap_err();
    assert!(matches!(err, rr_net::RaceError::NoCandidates), "{err:?}");
}

#[tokio::test]
async fn wrong_code_blocks_the_address_briefly() {
    let agent = start_agent_limited(true, &[], loopback_only(), None, LimitPolicy::default());
    let original = agent.code();
    let viewer = new_viewer("guesser");
    let err = viewer
        .pair(agent.addr, &wrong_code(&original))
        .await
        .unwrap_err();
    assert!(matches!(err, SessionError::PairingFailed), "{err:?}");

    // A second guess right away is refused before any TLS work...
    let err = viewer.pair(agent.addr, &original).await.unwrap_err();
    assert!(err.is_connection_refused(), "{err:?}");

    // ...and works once the 1 s block is over.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    viewer
        .pair(agent.addr, &original)
        .await
        .unwrap()
        .close()
        .await;
}
