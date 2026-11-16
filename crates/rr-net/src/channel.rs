//! The control stream: framed [`ControlMsg`]s over one QUIC bidirectional
//! stream (blueprint v2 §6.2, §6.3).

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use rr_proto::{ControlMsg, DisconnectReason, frame, limits};

use crate::SessionError;

/// Framed control messages over a QUIC stream pair.
#[derive(Debug)]
pub(crate) struct ControlChannel {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl ControlChannel {
    pub(crate) const fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
    }

    /// Sends one message.
    pub(crate) async fn send(&mut self, msg: &ControlMsg) -> Result<(), SessionError> {
        let bytes = frame::encode(msg, limits::CONTROL)?;
        self.send.write_all(&bytes).await?;
        Ok(())
    }

    /// Receives one message. The length prefix is checked against the
    /// control limit before the body buffer is allocated.
    pub(crate) async fn recv(&mut self) -> Result<ControlMsg, SessionError> {
        let mut prefix = [0u8; frame::PREFIX_LEN];
        self.recv.read_exact(&mut prefix).await?;
        let len = frame::body_len(prefix, limits::CONTROL)?;
        let mut body = vec![0u8; len];
        self.recv.read_exact(&mut body).await?;
        Ok(frame::decode(&body)?)
    }

    /// Receives one message and turns a `Disconnect` into an error.
    pub(crate) async fn recv_active(&mut self) -> Result<ControlMsg, SessionError> {
        match self.recv().await? {
            ControlMsg::Disconnect { reason } => Err(SessionError::Closed(reason)),
            msg => Ok(msg),
        }
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

/// Microseconds on a process-local monotonic clock, for `Ping` timestamps.
/// Only ever compared with values from the same process.
pub(crate) fn monotonic_us() -> u64 {
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
