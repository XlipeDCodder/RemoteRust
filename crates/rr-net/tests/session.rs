//! Screen-session tests over loopback: consent, `SessionStart`, the video,
//! cursor and input streams, and session end (blueprint v2 §6.5, §7.3).

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use rr_net::{
    Agent, AgentEvent, AgentOptions, AgentSession, DeviceIdentity, FailureKind, Grant, RemoteEvent,
    SessionError, SessionEvent, SessionRequest, SourceFilter, Viewer, ViewerSession,
};
use rr_proto::{
    AgentTimings, BoundedBytes, BoundedString, Codec, CursorMsg, DesktopState, DevicePublicKey,
    DisconnectReason, InputMsg, KeyCode, MonitorInfo, MouseButton, Permissions, VideoFrameHeader,
};
use tokio::sync::mpsc;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(10);

struct Setup {
    viewer: Viewer,
    agent: Agent,
    agent_key: DevicePublicKey,
    addr: SocketAddr,
    requests: mpsc::Receiver<SessionRequest>,
    events: mpsc::Receiver<AgentEvent>,
    endpoint: quinn::Endpoint,
}

impl Drop for Setup {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"");
    }
}

impl Setup {
    async fn connect(&self) -> ViewerSession {
        self.viewer
            .connect(self.addr, self.agent_key)
            .await
            .unwrap()
    }

    async fn next_request(&mut self) -> SessionRequest {
        timeout(WAIT, self.requests.recv()).await.unwrap().unwrap()
    }

    /// The next event the Agent reports that `pick` selects.
    async fn event<T>(&mut self, mut pick: impl FnMut(AgentEvent) -> Option<T>) -> T {
        timeout(WAIT, async {
            loop {
                let event = self.events.recv().await.expect("event feed open");
                if let Some(found) = pick(event) {
                    return found;
                }
            }
        })
        .await
        .unwrap()
    }
}

/// An Agent that already knows the Viewer, with sessions routed to the test.
fn setup(consent_timeout: Duration, sessions: bool) -> Setup {
    let viewer_identity = DeviceIdentity::generate().unwrap();
    let viewer_key = viewer_identity.public_key();
    let viewer = Viewer::new(viewer_identity, "test-viewer");

    let identity = DeviceIdentity::generate().unwrap();
    let agent_key = identity.public_key();
    let (tx, requests) = mpsc::channel(4);
    let (events_tx, events) = mpsc::channel(64);
    let options = AgentOptions {
        sessions: sessions.then_some(tx),
        consent_timeout,
        events: Some(events_tx),
        ..AgentOptions::new("test-agent")
    };
    let agent = Agent::new(identity, options, [viewer_key]).unwrap();
    let endpoint = agent.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn({
        let endpoint = endpoint.clone();
        let agent = agent.clone();
        async move {
            agent
                .serve(
                    endpoint,
                    SourceFilter::new(["127.0.0.0/8".parse().unwrap()]),
                )
                .await;
        }
    });
    Setup {
        viewer,
        agent,
        agent_key,
        addr,
        requests,
        events,
        endpoint,
    }
}

fn grant(permissions: Permissions) -> Grant {
    Grant {
        permissions,
        monitors: vec![MonitorInfo {
            id: 0,
            name: BoundedString::new("DISPLAY1").unwrap(),
            width: 1920,
            height: 1080,
            primary: true,
        }],
        monitor: 0,
        encoder: "test-encoder".to_owned(),
    }
}

fn header(frame_id: u64, len: usize) -> VideoFrameHeader {
    VideoFrameHeader {
        frame_id,
        capture_ts_us: frame_id * 1000,
        keyframe: frame_id == 0,
        codec: Codec::H264,
        width: 1920,
        height: 1080,
        timings: AgentTimings::default(),
        skipped: 0,
        len: u32::try_from(len).unwrap(),
    }
}

/// Starts a view-only session that the test accepts with `granted`.
async fn accepted(
    setup: &mut Setup,
    granted: Permissions,
) -> (rr_net::RemoteSession, AgentSession) {
    requested(setup, Permissions::VIEW, granted).await
}

/// Starts a session asking for `asked`, accepted with `granted`.
async fn requested(
    setup: &mut Setup,
    asked: Permissions,
    granted: Permissions,
) -> (rr_net::RemoteSession, AgentSession) {
    let session = setup.connect().await;
    let viewer = tokio::spawn(session.start(asked));
    let request = setup.next_request().await;
    assert_eq!(request.viewer_name(), "test-viewer");
    assert_eq!(request.permissions(), asked);
    let agent_session = request.accept(grant(granted)).await.unwrap();
    let remote = timeout(WAIT, viewer).await.unwrap().unwrap().unwrap();
    (remote, agent_session)
}

#[tokio::test]
async fn accepted_session_streams_frames_in_order() {
    let mut setup = setup(Duration::from_secs(30), true);
    let (mut remote, mut agent) = accepted(&mut setup, Permissions::VIEW).await;
    assert_eq!(remote.grant().permissions, Permissions::VIEW);
    assert_eq!(remote.grant().monitor, 0);
    assert_eq!(remote.agent_name(), "test-agent");

    let mut events = remote.take_events().unwrap();
    let event = timeout(WAIT, events.recv()).await.unwrap().unwrap();
    assert_eq!(event, RemoteEvent::Encoder("test-encoder".to_owned()));

    // A large keyframe followed by small frames, written while the Viewer
    // reads concurrently (the Agent's send window is smaller than 1 MiB).
    let frames: Vec<Vec<u8>> = vec![vec![1; 1024 * 1024], vec![2; 10], vec![3; 50_000]];
    let mut video = remote.take_video().unwrap();
    let reader = tokio::spawn(async move {
        let mut received = Vec::new();
        let mut buf = Vec::new();
        for _ in 0..3 {
            let header = video.recv(&mut buf).await.unwrap();
            received.push((header, buf.clone()));
        }
        received
    });
    for (id, payload) in frames.iter().enumerate() {
        let id = u64::try_from(id).unwrap();
        agent
            .video
            .send(&header(id, payload.len()), payload)
            .await
            .unwrap();
    }
    let received = timeout(WAIT, reader).await.unwrap().unwrap();
    for (id, ((header_in, payload_in), payload_out)) in received.iter().zip(&frames).enumerate() {
        let id = u64::try_from(id).unwrap();
        assert_eq!(*header_in, header(id, payload_out.len()));
        assert_eq!(payload_in, payload_out);
    }
    remote.close().await;
}

#[tokio::test]
async fn out_of_sequence_frames_are_refused_by_the_sender() {
    let mut setup = setup(Duration::from_secs(30), true);
    let (remote, mut agent) = accepted(&mut setup, Permissions::VIEW).await;
    let err = agent.video.send(&header(5, 3), &[0; 3]).await.unwrap_err();
    assert!(matches!(err, SessionError::Protocol(_)));
    let err = agent.video.send(&header(0, 4), &[0; 3]).await.unwrap_err();
    assert!(matches!(err, SessionError::Protocol(_)));
    remote.close().await;
}

#[tokio::test]
async fn keyframe_requests_reach_the_agent() {
    let mut setup = setup(Duration::from_secs(30), true);
    let (remote, mut agent) = accepted(&mut setup, Permissions::VIEW).await;
    remote.control().request_keyframe();
    let event = timeout(WAIT, agent.next_event()).await.unwrap();
    assert_eq!(event, Some(SessionEvent::KeyframeRequested));
    remote.close().await;
}

#[tokio::test]
async fn grant_never_exceeds_the_request() {
    let mut setup = setup(Duration::from_secs(30), true);
    let all = Permissions::VIEW.union(Permissions::CONTROL);
    let (remote, agent) = accepted(&mut setup, all).await;
    assert_eq!(remote.grant().permissions, Permissions::VIEW);
    assert_eq!(agent.permissions(), Permissions::VIEW);
    remote.close().await;
}

#[tokio::test]
async fn denied_session_is_refused() {
    let mut setup = setup(Duration::from_secs(30), true);
    let session = setup.connect().await;
    let viewer = tokio::spawn(session.start(Permissions::VIEW));
    setup.next_request().await.deny();
    let err = timeout(WAIT, viewer).await.unwrap().unwrap().unwrap_err();
    assert!(
        matches!(err, SessionError::Closed(DisconnectReason::ConsentDenied)),
        "{err:?}"
    );
}

#[tokio::test]
async fn unanswered_request_times_out() {
    let mut setup = setup(Duration::from_millis(300), true);
    let session = setup.connect().await;
    let viewer = tokio::spawn(session.start(Permissions::VIEW));
    let mut request = setup.next_request().await;
    // Keep the request alive without answering; it is withdrawn on timeout.
    timeout(WAIT, request.withdrawn()).await.unwrap();
    let err = timeout(WAIT, viewer).await.unwrap().unwrap().unwrap_err();
    assert!(
        matches!(err, SessionError::Closed(DisconnectReason::ConsentTimeout)),
        "{err:?}"
    );
    // Accepting too late fails instead of starting a session.
    assert!(request.accept(grant(Permissions::VIEW)).await.is_err());
}

#[tokio::test]
async fn agent_without_consent_handler_refuses() {
    let setup = setup(Duration::from_secs(30), false);
    let session = setup.connect().await;
    let err = session.start(Permissions::VIEW).await.unwrap_err();
    assert!(
        matches!(err, SessionError::Closed(DisconnectReason::ConsentDenied)),
        "{err:?}"
    );
}

#[tokio::test]
async fn request_without_view_is_refused() {
    let setup = setup(Duration::from_secs(30), true);
    let session = setup.connect().await;
    let err = session.start(Permissions::CONTROL).await.unwrap_err();
    assert!(
        matches!(err, SessionError::Closed(DisconnectReason::ConsentDenied)),
        "{err:?}"
    );
}

#[tokio::test]
async fn agent_ending_the_session_tells_the_viewer() {
    let mut setup = setup(Duration::from_secs(30), true);
    let (mut remote, agent) = accepted(&mut setup, Permissions::VIEW).await;
    let mut events = remote.take_events().unwrap();
    agent.handle().end(DisconnectReason::MediaFailed);
    let ended = timeout(WAIT, async {
        loop {
            match events.recv().await {
                Some(RemoteEvent::Ended(reason)) => return reason,
                Some(RemoteEvent::Encoder(_) | RemoteEvent::Desktop(_)) => {}
                None => return None,
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(ended, Some(DisconnectReason::MediaFailed));
    let mut video = remote.take_video().unwrap();
    assert!(video.recv(&mut Vec::new()).await.is_err());
}

#[tokio::test]
async fn viewer_leaving_ends_the_agent_session() {
    let mut setup = setup(Duration::from_secs(30), true);
    let (remote, mut agent) = accepted(&mut setup, Permissions::VIEW).await;
    remote.close().await;
    assert_eq!(timeout(WAIT, agent.next_event()).await.unwrap(), None);
    assert!(agent.handle().is_closed());
}

fn control() -> Permissions {
    Permissions::VIEW.union(Permissions::CONTROL)
}

#[tokio::test]
async fn input_reaches_the_agent_in_order() {
    let mut setup = setup(Duration::from_secs(30), true);
    let (mut remote, mut agent) = requested(&mut setup, control(), control()).await;
    assert_eq!(remote.grant().permissions, control());
    let mut input = remote.take_input().unwrap();
    let mut received = agent.take_input().unwrap();
    let sent = [
        InputMsg::Key {
            code: KeyCode::IntlRo,
            down: true,
        },
        InputMsg::Key {
            code: KeyCode::IntlRo,
            down: false,
        },
        InputMsg::MouseMove {
            monitor: 0,
            x: 65535,
            y: 0,
        },
        InputMsg::MouseButton {
            button: MouseButton::Left,
            down: true,
        },
        InputMsg::Wheel { dx: 0, dy: -120 },
        InputMsg::Held,
        InputMsg::ReleaseAll,
    ];
    for msg in &sent {
        input.send(msg).await.unwrap();
    }
    for msg in sent {
        let got = timeout(WAIT, received.recv()).await.unwrap().unwrap();
        assert_eq!(got, Some(msg));
    }
    // Finishing the stream reads as its end.
    input.finish();
    assert_eq!(timeout(WAIT, received.recv()).await.unwrap().unwrap(), None);
    assert_eq!(received.dropped(), 0);
    remote.close().await;
}

#[tokio::test]
async fn view_only_sessions_have_no_input() {
    let mut setup = setup(Duration::from_secs(30), true);
    // Asked to control, but the local user allowed viewing only.
    let (mut remote, mut agent) = requested(&mut setup, control(), Permissions::VIEW).await;
    assert_eq!(remote.grant().permissions, Permissions::VIEW);
    assert!(remote.take_input().is_none());
    assert!(agent.take_input().is_none());
    remote.close().await;
}

#[tokio::test]
async fn cursor_updates_reach_the_viewer() {
    let mut setup = setup(Duration::from_secs(30), true);
    let (mut remote, mut agent) = accepted(&mut setup, Permissions::VIEW).await;
    let mut cursor = remote.take_cursor().unwrap();
    let shape = CursorMsg::Shape {
        id: 3,
        hot_x: 1,
        hot_y: 2,
        width: 4,
        height: 4,
        rgba: BoundedBytes::new(vec![0x55; 64]).unwrap(),
    };
    let position = CursorMsg::Position {
        x: 100,
        y: 200,
        visible: true,
    };
    let mut sender = agent.take_cursor().unwrap();
    assert!(
        agent.take_cursor().is_none(),
        "the sender is handed out once"
    );
    sender.send(&shape).await.unwrap();
    sender.send(&position).await.unwrap();
    sender
        .send(&CursorMsg::UseCachedShape { id: 3 })
        .await
        .unwrap();
    assert_eq!(timeout(WAIT, cursor.recv()).await.unwrap().unwrap(), shape);
    assert_eq!(
        timeout(WAIT, cursor.recv()).await.unwrap().unwrap(),
        position
    );
    assert_eq!(
        timeout(WAIT, cursor.recv()).await.unwrap().unwrap(),
        CursorMsg::UseCachedShape { id: 3 }
    );
    // An inconsistent shape is refused before it reaches the wire.
    let broken = CursorMsg::Shape {
        id: 4,
        hot_x: 0,
        hot_y: 0,
        width: 4,
        height: 4,
        rgba: BoundedBytes::new(vec![0; 3]).unwrap(),
    };
    assert!(sender.send(&broken).await.is_err());
    // Video still flows next to the cursor.
    let mut video = remote.take_video().unwrap();
    agent.video.send(&header(0, 5), &[9; 5]).await.unwrap();
    let mut buf = Vec::new();
    let got = timeout(WAIT, video.recv(&mut buf)).await.unwrap().unwrap();
    assert_eq!(got, header(0, 5));
    remote.close().await;
}

/// How the Viewer's session ended, as its events report it.
async fn ending(events: &mut mpsc::Receiver<RemoteEvent>) -> Option<DisconnectReason> {
    timeout(WAIT, async {
        loop {
            match events.recv().await {
                Some(RemoteEvent::Ended(reason)) => return reason,
                Some(_) => {}
                None => return None,
            }
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn kill_switch_ends_the_session_within_200_ms() {
    let mut setup = setup(Duration::from_secs(30), true);
    let (mut remote, mut agent) = accepted(&mut setup, control()).await;
    let mut events = remote.take_events().unwrap();
    let started = Instant::now();
    setup.agent.end_all(DisconnectReason::StoppedLocally);
    assert_eq!(
        ending(&mut events).await,
        Some(DisconnectReason::StoppedLocally)
    );
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_millis(200), "took {elapsed:?}");
    // The media side sees the session end too.
    assert_eq!(timeout(WAIT, agent.next_event()).await.unwrap(), None);
    let reason = setup
        .event(|event| match event {
            AgentEvent::Disconnected { reason, .. } => Some(reason),
            _ => None,
        })
        .await;
    assert_eq!(reason, Some(DisconnectReason::StoppedLocally));
}

#[tokio::test]
async fn kill_switch_withdraws_a_pending_request() {
    let mut setup = setup(Duration::from_secs(30), true);
    let session = setup.connect().await;
    let viewer = tokio::spawn(session.start(Permissions::VIEW));
    let mut request = setup.next_request().await;
    setup.agent.end_all(DisconnectReason::StoppedLocally);
    timeout(WAIT, request.withdrawn()).await.unwrap();
    let err = timeout(WAIT, viewer).await.unwrap().unwrap().unwrap_err();
    assert!(
        matches!(err, SessionError::Closed(DisconnectReason::StoppedLocally)),
        "{err:?}"
    );
}

#[tokio::test]
async fn kill_switch_does_not_affect_later_sessions() {
    let mut setup = setup(Duration::from_secs(30), true);
    setup.agent.end_all(DisconnectReason::StoppedLocally);
    let (mut remote, agent) = accepted(&mut setup, Permissions::VIEW).await;
    let mut events = remote.take_events().unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!agent.handle().is_closed());
    agent.handle().end(DisconnectReason::Normal);
    assert_eq!(ending(&mut events).await, Some(DisconnectReason::Normal));
}

/// The next desktop state the Viewer's events report.
async fn next_desktop_state(events: &mut mpsc::Receiver<RemoteEvent>) -> DesktopState {
    timeout(WAIT, async {
        loop {
            match events.recv().await {
                Some(RemoteEvent::Desktop(state)) => return state,
                Some(_) => {}
                None => panic!("session ended"),
            }
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn desktop_state_reaches_the_viewer() {
    let mut setup = setup(Duration::from_secs(30), true);
    let (mut remote, agent) = accepted(&mut setup, control()).await;
    let mut events = remote.take_events().unwrap();
    agent
        .handle()
        .set_desktop_state(DesktopState::SecureDesktop);
    assert_eq!(
        next_desktop_state(&mut events).await,
        DesktopState::SecureDesktop
    );
    agent.handle().set_desktop_state(DesktopState::Normal);
    assert_eq!(next_desktop_state(&mut events).await, DesktopState::Normal);
}

/// The reason of the next `SessionRefused` event.
async fn next_refusal(setup: &mut Setup) -> DisconnectReason {
    setup
        .event(|event| match event {
            AgentEvent::SessionRefused { reason, .. } => Some(reason),
            _ => None,
        })
        .await
}

#[tokio::test]
async fn refused_device_must_wait_before_asking_again() {
    let mut setup = setup(Duration::from_secs(30), true);
    let session = setup.connect().await;
    let viewer = tokio::spawn(session.start(Permissions::VIEW));
    setup.next_request().await.deny();
    let err = timeout(WAIT, viewer).await.unwrap().unwrap().unwrap_err();
    assert!(matches!(
        err,
        SessionError::Closed(DisconnectReason::ConsentDenied)
    ));

    // Asking again at once: refused without bothering the local user.
    let session = setup.connect().await;
    let err = session.start(Permissions::VIEW).await.unwrap_err();
    assert!(
        matches!(err, SessionError::Closed(DisconnectReason::RateLimited)),
        "{err:?}"
    );
    assert!(setup.requests.try_recv().is_err());
    assert_eq!(
        next_refusal(&mut setup).await,
        DisconnectReason::ConsentDenied
    );
    assert_eq!(
        next_refusal(&mut setup).await,
        DisconnectReason::RateLimited
    );

    // After the backoff (1 s for a first refusal), the device may ask.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let session = setup.connect().await;
    let viewer = tokio::spawn(session.start(Permissions::VIEW));
    let request = setup.next_request().await;
    let agent = request.accept(grant(Permissions::VIEW)).await.unwrap();
    timeout(WAIT, viewer).await.unwrap().unwrap().unwrap();
    agent.handle().end(DisconnectReason::Normal);
}

#[tokio::test]
async fn failed_handshake_blocks_the_address_for_a_while() {
    let mut setup = setup(Duration::from_secs(30), true);
    // An unknown device: rejected during TLS (pairing is off).
    let stranger = Viewer::new(DeviceIdentity::generate().unwrap(), "stranger");
    assert!(stranger.connect(setup.addr, setup.agent_key).await.is_err());
    let (kind, blocked_for) = setup
        .event(|event| match event {
            AgentEvent::AuthFailed {
                kind, blocked_for, ..
            } => Some((kind, blocked_for)),
            _ => None,
        })
        .await;
    assert_eq!(kind, FailureKind::Handshake);
    assert_eq!(blocked_for, Duration::from_secs(1));

    // The same address is refused at once, even with a paired key...
    let refused = setup.viewer.connect(setup.addr, setup.agent_key).await;
    assert!(refused.is_err());
    setup
        .event(|event| matches!(event, AgentEvent::Blocked { .. }).then_some(()))
        .await;

    // ...until the block ends.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let session = setup.connect().await;
    session.close().await;
}
