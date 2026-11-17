//! The control stream: framed [`ControlMsg`]s over one QUIC bidirectional
//! stream (blueprint v2 §6.2, §6.3).

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use rr_proto::{ControlMsg, DisconnectReason, frame, limits};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::SessionError;

/// Messages read ahead by a [`ControlReader`] task.
const READ_AHEAD: usize = 8;

/// Framed control messages over a QUIC stream pair.
#[derive(Debug)]
pub(crate) struct ControlChannel {
    writer: ControlWriter,
    reader: ControlReader,
}

/// Sending half of the control stream.
#[derive(Debug)]
pub(crate) struct ControlWriter {
    send: quinn::SendStream,
}

/// Receiving half of the control stream.
#[derive(Debug)]
pub(crate) struct ControlReader {
    recv: quinn::RecvStream,
}

impl ControlChannel {
    pub(crate) const fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self {
            writer: ControlWriter { send },
            reader: ControlReader { recv },
        }
    }

    /// Splits the channel so reading and writing can run concurrently.
    pub(crate) fn split(self) -> (ControlWriter, ControlReader) {
        (self.writer, self.reader)
    }

    /// Sends one message.
    pub(crate) async fn send(&mut self, msg: &ControlMsg) -> Result<(), SessionError> {
        self.writer.send(msg).await
    }

    /// Receives one message.
    pub(crate) async fn recv(&mut self) -> Result<ControlMsg, SessionError> {
        self.reader.recv().await
    }

    /// Receives one message and turns a `Disconnect` into an error.
    pub(crate) async fn recv_active(&mut self) -> Result<ControlMsg, SessionError> {
        match self.recv().await? {
            ControlMsg::Disconnect { reason } => Err(SessionError::Closed(reason)),
            msg => Ok(msg),
        }
    }

    /// See [`ControlWriter::goodbye`].
    pub(crate) async fn goodbye(&mut self, reason: DisconnectReason) {
        self.writer.goodbye(reason).await;
    }
}

impl ControlWriter {
    /// Sends one message.
    pub(crate) async fn send(&mut self, msg: &ControlMsg) -> Result<(), SessionError> {
        let bytes = frame::encode(msg, limits::CONTROL)?;
        self.send.write_all(&bytes).await?;
        Ok(())
    }

    /// Best-effort goodbye: sends `Disconnect`, finishes the stream and
    /// waits until the peer acknowledged it. Closing the connection earlier
    /// would discard the message, leaving the peer without a reason.
    /// Errors are ignored because the peer may already be gone; callers
    /// bound the wait with a timeout.
    pub(crate) async fn goodbye(&mut self, reason: DisconnectReason) {
        if self.send(&ControlMsg::Disconnect { reason }).await.is_ok() && self.send.finish().is_ok()
        {
            let _ = self.send.stopped().await;
        }
    }
}

impl ControlReader {
    /// Receives one message. The length prefix is checked against the
    /// control limit before the body buffer is allocated.
    ///
    /// Not cancel-safe (a partial read would be lost): use it from one task
    /// only, e.g. through [`ControlReader::spawn`].
    pub(crate) async fn recv(&mut self) -> Result<ControlMsg, SessionError> {
        let mut prefix = [0u8; frame::PREFIX_LEN];
        self.recv.read_exact(&mut prefix).await?;
        let len = frame::body_len(prefix, limits::CONTROL)?;
        let mut body = vec![0u8; len];
        self.recv.read_exact(&mut body).await?;
        Ok(frame::decode(&body)?)
    }

    /// Reads messages on a task of their own, so callers can `select!` on
    /// the returned channel safely. The task forwards the first error and
    /// stops; it also stops when the receiver is dropped.
    pub(crate) fn spawn(
        mut self,
    ) -> (
        mpsc::Receiver<Result<ControlMsg, SessionError>>,
        JoinHandle<()>,
    ) {
        let (tx, rx) = mpsc::channel(READ_AHEAD);
        let task = tokio::spawn(async move {
            loop {
                let result = self.recv().await;
                let failed = result.is_err();
                if tx.send(result).await.is_err() || failed {
                    return;
                }
            }
        });
        (rx, task)
    }
}

/// Microseconds on a process-local monotonic clock, for `Ping` timestamps
/// and video capture times. Only ever compared with values from the same
/// process.
#[must_use]
pub fn monotonic_us() -> u64 {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let elapsed = EPOCH.get_or_init(Instant::now).elapsed();
    u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX)
}

/// Round-trip time for a `Pong` echoing `t_us`.
pub(crate) fn rtt_since(t_us: u64) -> Duration {
    Duration::from_micros(monotonic_us().saturating_sub(t_us))
}

/// The short label a peer sees for each local failure, used when closing.
pub(crate) const fn disconnect_reason_for(err: &SessionError) -> DisconnectReason {
    match err {
        SessionError::Refused(reason) => *reason,
        SessionError::Timeout => DisconnectReason::Timeout,
        SessionError::PairingFailed => DisconnectReason::PairingFailed,
        _ => DisconnectReason::ProtocolError,
    }
}
