//! Screen-session tests over loopback: consent, `SessionStart`, the video
//! stream and session end (blueprint v2 §6.5, §7.3).

use std::net::SocketAddr;
use std::time::Duration;

use rr_net::{
    Agent, AgentOptions, AgentSession, DeviceIdentity, Grant, RemoteEvent, SessionError,
    SessionEvent, SessionRequest, SourceFilter, Viewer, ViewerSession,
};
use rr_proto::{
    AgentTimings, BoundedString, Codec, DevicePublicKey, DisconnectReason, MonitorInfo,
    Permissions, VideoFrameHeader,
};
use tokio::sync::mpsc;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(10);

struct Setup {
    viewer: Viewer,
    agent_key: DevicePublicKey,
    addr: SocketAddr,
    requests: mpsc::Receiver<SessionRequest>,
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
}

/// An Agent that already knows the Viewer, with sessions routed to the test.
fn setup(consent_timeout: Duration, sessions: bool) -> Setup {
    let viewer_identity = DeviceIdentity::generate().unwrap();
    let viewer_key = viewer_identity.public_key();
    let viewer = Viewer::new(viewer_identity, "test-viewer");

    let identity = DeviceIdentity::generate().unwrap();
    let agent_key = identity.public_key();
    let (tx, requests) = mpsc::channel(4);
    let options = AgentOptions {
        sessions: sessions.then_some(tx),
        consent_timeout,
        ..AgentOptions::new("test-agent")
    };
    let agent = Agent::new(identity, options, [viewer_key]).unwrap();
    let endpoint = agent.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn({
        let endpoint = endpoint.clone();
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
        agent_key,
        addr,
        requests,
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

/// Starts a session that the test accepts with `granted`.
async fn accepted(
    setup: &mut Setup,
    granted: Permissions,
) -> (rr_net::RemoteSession, AgentSession) {
    let session = setup.connect().await;
    let viewer = tokio::spawn(session.start(Permissions::VIEW));
    let request = setup.next_request().await;
    assert_eq!(request.viewer_name(), "test-viewer");
    assert_eq!(request.permissions(), Permissions::VIEW);
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
                Some(RemoteEvent::Encoder(_)) => {}
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
