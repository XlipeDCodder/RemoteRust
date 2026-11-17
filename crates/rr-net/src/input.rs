//! The input stream: keyboard and mouse from the Viewer to the Agent
//! (blueprint v2 §6.2, §6.3, §8.7). Framing lives in [`rr_proto::input`].
//!
//! The Agent caps the stream at [`MAX_EVENTS_PER_SECOND`]: beyond it,
//! pointer moves, wheel steps and `Held` are dropped (the next one carries
//! the newer state anyway), while keys and buttons are never dropped,
//! because a lost release would leave something pressed. A peer that sends
//! more keys and buttons than the cap allows is cut off.

use std::time::{Duration, Instant};

use rr_proto::frame::{self, PREFIX_LEN};
use rr_proto::{InputMsg, StreamKind, limits};

use crate::SessionError;
use crate::streams::{self, Pending};

/// Input events per second the Agent accepts (blueprint v2 §6.3).
pub const MAX_EVENTS_PER_SECOND: u64 = 2000;

/// How often the Agent logs that it is dropping input.
const DROP_LOG_PERIOD: Duration = Duration::from_secs(1);

/// Writes input on the Viewer side. The stream is opened with the first
/// message.
#[derive(Debug)]
pub struct InputSender {
    conn: quinn::Connection,
    stream: Option<quinn::SendStream>,
}

impl InputSender {
    pub(crate) const fn new(conn: quinn::Connection) -> Self {
        Self { conn, stream: None }
    }

    /// Sends one message. This waits while QUIC flow control holds the
    /// stream back.
    ///
    /// # Errors
    /// Framing or stream errors; the session is over.
    pub async fn send(&mut self, msg: &InputMsg) -> Result<(), SessionError> {
        let bytes = frame::encode(msg, limits::INPUT)?;
        let stream = match &mut self.stream {
            Some(stream) => stream,
            None => self
                .stream
                .insert(streams::open(&self.conn, StreamKind::Input).await?),
        };
        stream.write_all(&bytes).await?;
        Ok(())
    }

    /// Finishes the stream: the Agent releases everything still pressed.
    pub fn finish(&mut self) {
        if let Some(stream) = &mut self.stream {
            let _ = stream.finish();
        }
    }
}

/// Reads input on the Agent side, enforcing the rate cap.
#[derive(Debug)]
pub struct InputReceiver {
    stream: Pending,
    limiter: RateLimiter,
    dropped: u64,
    last_drop_log: Option<Instant>,
}

impl InputReceiver {
    pub(crate) const fn new(stream: Pending) -> Self {
        Self {
            stream,
            limiter: RateLimiter::new(MAX_EVENTS_PER_SECOND),
            dropped: 0,
            last_drop_log: None,
        }
    }

    /// The next message, waiting for the Viewer to open the stream first;
    /// `None` once the Viewer finished it.
    ///
    /// Not cancel-safe (a partial read would be lost): call it from one task
    /// only.
    ///
    /// # Errors
    /// Framing errors, a flood of keys or buttons
    /// ([`SessionError::Protocol`]) or stream errors.
    pub async fn recv(&mut self) -> Result<Option<InputMsg>, SessionError> {
        loop {
            let stream = self.stream.get().await?;
            let mut prefix = [0u8; PREFIX_LEN];
            match stream.read_exact(&mut prefix).await {
                Ok(()) => {}
                Err(quinn::ReadExactError::FinishedEarly(0)) => return Ok(None),
                Err(err) => return Err(err.into()),
            }
            let len = frame::body_len(prefix, limits::INPUT)?;
            let mut body = [0u8; limits::INPUT as usize];
            let body = body
                .get_mut(..len)
                .ok_or(SessionError::Protocol("input message too long"))?;
            stream.read_exact(body).await?;
            let msg: InputMsg = frame::decode(body)?;
            let now = Instant::now();
            match self.limiter.admit(now, &msg) {
                Admit::Pass => return Ok(Some(msg)),
                Admit::Drop => self.note_drop(now),
                Admit::Flood => return Err(SessionError::Protocol("input flood")),
            }
        }
    }

    /// Messages dropped by the rate cap so far.
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    fn note_drop(&mut self, now: Instant) {
        self.dropped = self.dropped.saturating_add(1);
        let due = self
            .last_drop_log
            .is_none_or(|last| now.saturating_duration_since(last) >= DROP_LOG_PERIOD);
        if due {
            self.last_drop_log = Some(now);
            tracing::warn!(
                dropped = self.dropped,
                "input above {MAX_EVENTS_PER_SECOND} events/s: dropping pointer moves"
            );
        }
    }
}

/// What the rate cap decides for one message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admit {
    Pass,
    /// Over the cap, and safe to lose.
    Drop,
    /// Over the cap with a key or button: the peer is misbehaving.
    Flood,
}

/// Token bucket: `rate` tokens per second, holding at most one second's
/// worth. Tokens are counted in millionths to stay in integers.
#[derive(Debug)]
struct RateLimiter {
    rate: u64,
    tokens: u64,
    last: Option<Instant>,
}

/// Token units per whole token.
const UNIT: u64 = 1_000_000;

impl RateLimiter {
    const fn new(rate: u64) -> Self {
        Self {
            rate,
            tokens: rate.saturating_mul(UNIT),
            last: None,
        }
    }

    fn admit(&mut self, now: Instant, msg: &InputMsg) -> Admit {
        if let Some(last) = self.last {
            let elapsed =
                u64::try_from(now.saturating_duration_since(last).as_micros()).unwrap_or(u64::MAX);
            // `rate` tokens per second = `rate` units per microsecond.
            self.tokens = self
                .tokens
                .saturating_add(elapsed.saturating_mul(self.rate))
                .min(self.rate.saturating_mul(UNIT));
        }
        self.last = Some(now);
        if let Some(rest) = self.tokens.checked_sub(UNIT) {
            self.tokens = rest;
            return Admit::Pass;
        }
        match msg {
            InputMsg::MouseMove { .. } | InputMsg::Wheel { .. } | InputMsg::Held => Admit::Drop,
            InputMsg::Key { .. } | InputMsg::MouseButton { .. } | InputMsg::ReleaseAll => {
                Admit::Flood
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use rr_proto::{KeyCode, MouseButton};

    use super::*;

    const MOVE: InputMsg = InputMsg::MouseMove {
        monitor: 0,
        x: 1,
        y: 1,
    };
    const KEY: InputMsg = InputMsg::Key {
        code: KeyCode::KeyA,
        down: true,
    };

    #[test]
    fn the_cap_drops_moves_and_refuses_floods_of_keys() {
        let start = Instant::now();
        let mut limiter = RateLimiter::new(10);
        for _ in 0..10 {
            assert_eq!(limiter.admit(start, &MOVE), Admit::Pass);
        }
        assert_eq!(limiter.admit(start, &MOVE), Admit::Drop);
        assert_eq!(limiter.admit(start, &InputMsg::Held), Admit::Drop);
        assert_eq!(limiter.admit(start, &KEY), Admit::Flood);
        let button = InputMsg::MouseButton {
            button: MouseButton::Left,
            down: false,
        };
        assert_eq!(limiter.admit(start, &button), Admit::Flood);
    }

    #[test]
    fn tokens_refill_over_time_up_to_one_second() {
        let start = Instant::now();
        let mut limiter = RateLimiter::new(10);
        for _ in 0..10 {
            assert_eq!(limiter.admit(start, &KEY), Admit::Pass);
        }
        // 100 ms at 10/s = one token.
        let later = start + Duration::from_millis(100);
        assert_eq!(limiter.admit(later, &KEY), Admit::Pass);
        assert_eq!(limiter.admit(later, &MOVE), Admit::Drop);
        // A long pause refills at most a second's worth.
        let much_later = later + Duration::from_secs(60);
        for _ in 0..10 {
            assert_eq!(limiter.admit(much_later, &KEY), Admit::Pass);
        }
        assert_eq!(limiter.admit(much_later, &KEY), Admit::Flood);
    }

    #[test]
    fn human_input_never_hits_the_cap() {
        // 1000 Hz pointer plus 30 keys/s for ten seconds.
        let start = Instant::now();
        let mut limiter = RateLimiter::new(MAX_EVENTS_PER_SECOND);
        for ms in 0..10_000u64 {
            let now = start + Duration::from_millis(ms);
            assert_eq!(limiter.admit(now, &MOVE), Admit::Pass);
            if ms % 33 == 0 {
                assert_eq!(limiter.admit(now, &KEY), Admit::Pass);
            }
        }
    }
}
