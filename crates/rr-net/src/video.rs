//! The video stream: one ordered, unidirectional QUIC stream from the
//! Agent (blueprint v2 §6.2, §6.3). Framing lives in [`rr_proto::video`].

use rr_proto::frame::PREFIX_LEN;
use rr_proto::{VideoFrameHeader, limits, video};

use crate::SessionError;

/// Writes encoded frames on the Agent side.
#[derive(Debug)]
pub struct VideoSender {
    stream: quinn::SendStream,
    next_id: u64,
}

impl VideoSender {
    pub(crate) const fn new(stream: quinn::SendStream) -> Self {
        Self { stream, next_id: 0 }
    }

    /// The `frame_id` the next frame must carry.
    #[must_use]
    pub const fn next_frame_id(&self) -> u64 {
        self.next_id
    }

    /// Sends one frame. This waits while QUIC flow or congestion control
    /// holds the stream back; callers skip capturing meanwhile, so the next
    /// frame shows the latest screen ("latest frame wins").
    ///
    /// # Errors
    /// [`SessionError::Protocol`] if the header does not describe
    /// `bitstream` or carries the wrong `frame_id`; framing or stream errors.
    pub async fn send(
        &mut self,
        header: &VideoFrameHeader,
        bitstream: &[u8],
    ) -> Result<(), SessionError> {
        if usize::try_from(header.len).ok() != Some(bitstream.len()) {
            return Err(SessionError::Protocol("video header length mismatch"));
        }
        if header.frame_id != self.next_id {
            return Err(SessionError::Protocol("video frame id out of sequence"));
        }
        let head = video::encode_header(header)?;
        self.stream.write_all(&head).await?;
        self.stream.write_all(bitstream).await?;
        self.next_id = self.next_id.saturating_add(1);
        Ok(())
    }
}

/// Reads encoded frames on the Viewer side.
#[derive(Debug)]
pub struct VideoReceiver {
    conn: quinn::Connection,
    /// Accepted on the first `recv`: QUIC announces a stream to the peer
    /// only when its first bytes are sent.
    stream: Option<quinn::RecvStream>,
    next_id: u64,
}

impl VideoReceiver {
    pub(crate) const fn new(conn: quinn::Connection) -> Self {
        Self {
            conn,
            stream: None,
            next_id: 0,
        }
    }

    async fn stream(&mut self) -> Result<&mut quinn::RecvStream, SessionError> {
        if self.stream.is_none() {
            self.stream = Some(self.conn.accept_uni().await?);
        }
        self.stream
            .as_mut()
            .ok_or(SessionError::Stream("video stream missing"))
    }

    /// Receives the next frame into `bitstream` (resized; its capacity is
    /// reused). The header is size-checked before the bitstream buffer
    /// grows, and frame ids must follow each other without gaps.
    ///
    /// Not cancel-safe: call it from one task only.
    ///
    /// # Errors
    /// Framing errors, a sequence gap ([`SessionError::Protocol`]) or a
    /// stream error when the session ends.
    pub async fn recv(
        &mut self,
        bitstream: &mut Vec<u8>,
    ) -> Result<VideoFrameHeader, SessionError> {
        let expected = self.next_id;
        let stream = self.stream().await?;
        let mut prefix = [0u8; PREFIX_LEN];
        stream.read_exact(&mut prefix).await?;
        let len = video::header_len(prefix)?;
        let mut head = [0u8; limits::VIDEO_HEADER as usize];
        let head = head
            .get_mut(..len)
            .ok_or(SessionError::Protocol("video header too long"))?;
        stream.read_exact(head).await?;
        let header = video::decode_header(head)?;
        if header.frame_id != expected {
            return Err(SessionError::Protocol("video frame id out of sequence"));
        }
        let len = usize::try_from(header.len)
            .map_err(|_| SessionError::Protocol("video frame too long"))?;
        bitstream.clear();
        bitstream.resize(len, 0);
        stream.read_exact(bitstream).await?;
        self.next_id = expected.saturating_add(1);
        Ok(header)
    }
}
