//! Unidirectional streams (blueprint v2 §6.2). Each one starts with a
//! one-byte [`StreamKind`] tag, and each kind may be opened at most once per
//! session: a repeated or unexpected kind closes the connection.

use std::time::Duration;

use rr_proto::StreamKind;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::SessionError;
use crate::agent::CLOSE_REFUSED;

/// Longest wait for the tag of a stream the peer opened. QUIC announces a
/// stream together with its first bytes, so this only trips on a peer that
/// opens a stream with an empty frame.
const TAG_TIMEOUT: Duration = Duration::from_secs(2);

/// Scheduling priority of each stream kind (higher is sent first): input
/// beats the cursor, which beats video (blueprint v2 §6.2).
const fn priority(kind: StreamKind) -> i32 {
    match kind {
        StreamKind::Input => 10,
        StreamKind::Cursor => 5,
        StreamKind::Video => 0,
    }
}

/// Opens a stream of `kind` and writes its tag.
pub(crate) async fn open(
    conn: &quinn::Connection,
    kind: StreamKind,
) -> Result<quinn::SendStream, SessionError> {
    let mut stream = conn.open_uni().await?;
    // Only fails on a stream that is already closed.
    let _ = stream.set_priority(priority(kind));
    stream.write_all(&[kind.tag()]).await?;
    Ok(stream)
}

/// Reads the tag of a stream the peer opened.
pub(crate) async fn read_tag(stream: &mut quinn::RecvStream) -> Result<StreamKind, SessionError> {
    let mut tag = [0u8; 1];
    timeout(TAG_TIMEOUT, stream.read_exact(&mut tag)).await??;
    let [tag] = tag;
    StreamKind::from_tag(tag).ok_or(SessionError::Protocol("unknown stream kind"))
}

/// A stream that is handed over once the peer opens it.
#[derive(Debug)]
pub(crate) enum Pending {
    Waiting(oneshot::Receiver<quinn::RecvStream>),
    Ready(quinn::RecvStream),
}

impl Pending {
    /// Waits for the stream (cancel-safe), then returns it.
    pub(crate) async fn get(&mut self) -> Result<&mut quinn::RecvStream, SessionError> {
        if let Self::Waiting(receiver) = self {
            let stream = receiver
                .await
                .map_err(|_| SessionError::Stream("the stream was never opened"))?;
            *self = Self::Ready(stream);
        }
        match self {
            Self::Ready(stream) => Ok(stream),
            Self::Waiting(_) => Err(SessionError::Stream("the stream was never opened")),
        }
    }
}

/// Viewer side: hands the Agent's video and cursor streams over as they
/// arrive. Anything else (an unknown or repeated kind) closes the
/// connection.
pub(crate) fn route_agent_streams(conn: quinn::Connection) -> (Pending, Pending, JoinHandle<()>) {
    let (video_tx, video_rx) = oneshot::channel();
    let (cursor_tx, cursor_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut video = Some(video_tx);
        let mut cursor = Some(cursor_tx);
        while video.is_some() || cursor.is_some() {
            let Ok(mut stream) = conn.accept_uni().await else {
                return;
            };
            let slot = match read_tag(&mut stream).await {
                Ok(StreamKind::Video) => video.take(),
                Ok(StreamKind::Cursor) => cursor.take(),
                Ok(StreamKind::Input) => None,
                Err(err) => {
                    tracing::debug!(error = %err, "bad stream from the agent");
                    None
                }
            };
            let Some(slot) = slot else {
                tracing::warn!("the agent opened an unexpected stream, closing");
                conn.close(CLOSE_REFUSED, b"unexpected stream");
                return;
            };
            // The receiver may be gone already (session closing).
            let _ = slot.send(stream);
        }
    });
    (
        Pending::Waiting(video_rx),
        Pending::Waiting(cursor_rx),
        task,
    )
}
