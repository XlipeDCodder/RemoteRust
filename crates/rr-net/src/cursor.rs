//! The cursor stream: pointer position and shape from the Agent
//! (blueprint v2 §6.2, §8.2 rule 3). Framing and checks live in
//! [`rr_proto::cursor`].

use rr_proto::frame::{self, PREFIX_LEN};
use rr_proto::{CursorMsg, StreamKind, cursor, limits};

use crate::SessionError;
use crate::streams::{self, Pending};

/// Writes cursor updates on the Agent side. The stream is opened with the
/// first message, so sessions whose cursor is part of the video (Wayland)
/// never open it.
#[derive(Debug)]
pub struct CursorSender {
    conn: quinn::Connection,
    stream: Option<quinn::SendStream>,
}

impl CursorSender {
    pub(crate) const fn new(conn: quinn::Connection) -> Self {
        Self { conn, stream: None }
    }

    /// Sends one update.
    ///
    /// # Errors
    /// An inconsistent shape ([`SessionError::Frame`]) or stream errors.
    pub async fn send(&mut self, msg: &CursorMsg) -> Result<(), SessionError> {
        let bytes = cursor::encode(msg)?;
        let stream = match &mut self.stream {
            Some(stream) => stream,
            None => self
                .stream
                .insert(streams::open(&self.conn, StreamKind::Cursor).await?),
        };
        stream.write_all(&bytes).await?;
        Ok(())
    }
}

/// Reads cursor updates on the Viewer side.
#[derive(Debug)]
pub struct CursorReceiver {
    stream: Pending,
    body: Vec<u8>,
}

impl CursorReceiver {
    pub(crate) const fn new(stream: Pending) -> Self {
        Self {
            stream,
            body: Vec::new(),
        }
    }

    /// The next update, waiting for the Agent to open the stream first (it
    /// may never do so). The length prefix is checked before the buffer
    /// grows, and shapes are validated.
    ///
    /// Not cancel-safe: call it from one task only.
    ///
    /// # Errors
    /// Framing errors or stream errors when the session ends.
    pub async fn recv(&mut self) -> Result<CursorMsg, SessionError> {
        let stream = self.stream.get().await?;
        let mut prefix = [0u8; PREFIX_LEN];
        stream.read_exact(&mut prefix).await?;
        let len = frame::body_len(prefix, limits::CURSOR)?;
        self.body.clear();
        self.body.resize(len, 0);
        stream.read_exact(&mut self.body).await?;
        Ok(cursor::decode(&self.body)?)
    }
}
