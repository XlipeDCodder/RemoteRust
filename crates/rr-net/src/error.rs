//! Error type for connections and sessions.

use rr_proto::{DisconnectReason, FrameError};

/// Errors while setting up, authenticating or running a connection.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// rustls rejected the TLS configuration.
    #[error("TLS setup failed")]
    TlsSetup(#[from] rustls::Error),

    /// The crypto provider lacks the cipher suite QUIC needs.
    #[error("QUIC setup failed: no TLS 1.3 initial cipher suite")]
    NoInitialCipherSuite,

    /// A socket could not be opened.
    #[error("socket error")]
    Io(#[from] std::io::Error),

    /// The connection attempt could not start.
    #[error("cannot start connection")]
    Connect(#[from] quinn::ConnectError),

    /// The connection failed or was closed, including TLS handshake
    /// failures such as an unknown or mismatched device key (see
    /// [`SessionError::is_tls_rejection`]).
    #[error("connection failed")]
    Connection(#[from] quinn::ConnectionError),

    /// A stream was reset, stopped or finished early.
    #[error("control stream closed: {0}")]
    Stream(&'static str),

    /// The peer sent an oversized or malformed frame.
    #[error("invalid frame")]
    Frame(#[from] FrameError),

    /// A step did not finish within its deadline.
    #[error("timed out")]
    Timeout,

    /// The peer broke the protocol.
    #[error("protocol violation: {0}")]
    Protocol(&'static str),

    /// The peer ended the session with `Disconnect`.
    #[error("the peer closed the session ({0:?})")]
    Closed(DisconnectReason),

    /// This side refused the peer (sent as `Disconnect`).
    #[error("refused the peer ({0:?})")]
    Refused(DisconnectReason),

    /// Wrong session code, or someone tampered with the connection.
    #[error("pairing failed: wrong session code or tampered connection")]
    PairingFailed,

    /// TLS keying material for channel binding was unavailable.
    #[error("cannot derive TLS channel binding")]
    ChannelBinding,

    /// The OS random generator failed.
    #[error("random number generator failed")]
    Random,
}

impl SessionError {
    /// True if the connection ended with a TLS alert: on the Viewer this
    /// usually means the Agent does not know this device (or pairing is
    /// closed), or that the Agent's key is not the pinned one.
    #[must_use]
    pub fn is_tls_rejection(&self) -> bool {
        let Self::Connection(err) = self else {
            return false;
        };
        let code = match err {
            quinn::ConnectionError::ConnectionClosed(close) => close.error_code,
            quinn::ConnectionError::TransportError(err) => err.code,
            _ => return false,
        };
        // RFC 9000 §20.1: CRYPTO_ERROR is 0x0100–0x01ff (TLS alert + 0x100).
        (0x100..0x200).contains(&u64::from(code))
    }

    /// Whether the Agent refused the connection before any TLS work: it
    /// had too many handshakes pending, or this address failed too often
    /// recently and must wait (blueprint v2 §7.5).
    #[must_use]
    pub fn is_connection_refused(&self) -> bool {
        // RFC 9000 §20.1: CONNECTION_REFUSED.
        matches!(
            self,
            Self::Connection(quinn::ConnectionError::ConnectionClosed(close))
                if u64::from(close.error_code) == 0x2
        )
    }
}

impl From<tokio::time::error::Elapsed> for SessionError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        Self::Timeout
    }
}

impl From<quinn::WriteError> for SessionError {
    fn from(err: quinn::WriteError) -> Self {
        match err {
            quinn::WriteError::ConnectionLost(err) => Self::Connection(err),
            quinn::WriteError::Stopped(_) => Self::Stream("stopped by peer"),
            quinn::WriteError::ClosedStream => Self::Stream("already closed"),
            quinn::WriteError::ZeroRttRejected => Self::Stream("0-RTT rejected"),
        }
    }
}

impl From<quinn::ReadExactError> for SessionError {
    fn from(err: quinn::ReadExactError) -> Self {
        match err {
            quinn::ReadExactError::FinishedEarly(_) => Self::Stream("finished by peer"),
            quinn::ReadExactError::ReadError(err) => match err {
                quinn::ReadError::ConnectionLost(err) => Self::Connection(err),
                quinn::ReadError::Reset(_) => Self::Stream("reset by peer"),
                quinn::ReadError::ClosedStream => Self::Stream("already closed"),
                quinn::ReadError::ZeroRttRejected => Self::Stream("0-RTT rejected"),
                quinn::ReadError::IllegalOrderedRead => Self::Stream("illegal ordered read"),
            },
        }
    }
}
