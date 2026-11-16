//! Attended pairing: single-use session codes and SPAKE2 bound to TLS
//! (blueprint v2 §7.2, §7.3).
//!
//! 1. The Agent shows a 6-digit code; the Viewer's user types it in.
//! 2. Both run SPAKE2 with the code as password. The code never crosses the
//!    network and a recorded run allows no offline guessing.
//! 3. Both derive confirmation keys from the SPAKE2 key, salted with the TLS
//!    exporter and bound to both device keys. A man in the middle would
//!    terminate two TLS sessions with different exporters and keys, so the
//!    MACs cannot match.
//! 4. The Viewer proves knowledge first; the Agent counts every attempt and
//!    rotates the code after a success or after `max_attempts` attempts.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use ring::rand::{SecureRandom as _, SystemRandom};
use ring::{digest, hkdf, hmac};
use rr_config::AttendedConfig;
use rr_proto::{BoundedBytes, ControlMsg, DevicePublicKey, DisconnectReason};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use tokio::sync::watch;
use zeroize::Zeroizing;

use crate::SessionError;
use crate::channel::ControlChannel;
use crate::tls::PAIRING_EXPORTER_LABEL;

/// Number of digits in a session code.
pub const CODE_DIGITS: usize = 6;

const SPAKE_ID_VIEWER: &[u8] = b"rustremote/1 viewer";
const SPAKE_ID_AGENT: &[u8] = b"rustremote/1 agent";
const TRANSCRIPT_DOMAIN: &[u8] = b"rustremote/1 pairing transcript\0";
const VIEWER_CONFIRM_LABEL: &[u8] = b"rustremote/1 viewer confirm";
const AGENT_CONFIRM_LABEL: &[u8] = b"rustremote/1 agent confirm";

/// A 6-digit, single-use session code. A secret: `Debug` hides it, there is
/// no `Display`, and memory is wiped on drop. Show it only through
/// [`SessionCode::expose`], and never log it.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionCode(Zeroizing<[u8; CODE_DIGITS]>);

impl SessionCode {
    /// Draws a uniformly random code from the OS generator.
    ///
    /// # Errors
    /// [`SessionError::Random`] if the OS generator fails.
    pub fn generate() -> Result<Self, SessionError> {
        let rng = SystemRandom::new();
        let mut digits = Zeroizing::new([b'0'; CODE_DIGITS]);
        let mut slots = digits.iter_mut();
        let mut slot = slots.next();
        while slot.is_some() {
            let mut pool = Zeroizing::new([0u8; 16]);
            rng.fill(pool.as_mut_slice())
                .map_err(|_| SessionError::Random)?;
            // Rejection sampling: 250 = 25 * 10, so each digit is uniform.
            for &byte in pool.iter().filter(|&&byte| byte < 250) {
                let Some(current) = slot.take() else { break };
                *current = b'0'.wrapping_add(byte.checked_rem(10).unwrap_or(0));
                slot = slots.next();
            }
        }
        Ok(Self(digits))
    }

    /// Parses user input, ignoring spaces and dashes (`123 456`, `123-456`).
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let mut digits = Zeroizing::new([b'0'; CODE_DIGITS]);
        let mut slots = digits.iter_mut();
        for c in text.bytes().filter(|c| !matches!(c, b' ' | b'-')) {
            if !c.is_ascii_digit() {
                return None;
            }
            *slots.next()? = c;
        }
        slots.next().is_none().then(|| Self(digits))
    }

    /// The code as text, for showing it to the local user only.
    #[must_use]
    pub fn expose(&self) -> &str {
        std::str::from_utf8(self.0.as_slice()).unwrap_or_default()
    }

    fn password(&self) -> Password {
        Password::new(self.0.as_slice())
    }
}

impl fmt::Debug for SessionCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionCode(******)")
    }
}

/// Rotation and rate-limit policy for session codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodePolicy {
    /// Lifetime of a code.
    pub ttl: Duration,
    /// Attempts allowed per code.
    pub max_attempts: u8,
    /// Delay after the first failure; doubles on each further failure.
    pub backoff_base: Duration,
    /// Ceiling for the delay.
    pub backoff_max: Duration,
}

impl CodePolicy {
    /// Policy from the attended-access configuration, with the backoff of
    /// blueprint v2 §7.5 (1 s, 2 s, 4 s, … capped at 5 min).
    #[must_use]
    pub fn from_config(config: &AttendedConfig) -> Self {
        Self {
            ttl: Duration::from_secs(u64::from(config.code_ttl_secs)),
            max_attempts: config.max_code_attempts,
            backoff_base: Duration::from_secs(1),
            backoff_max: Duration::from_secs(300),
        }
    }

    fn backoff(&self, failures: u32) -> Duration {
        let factor = 2u32.saturating_pow(failures.saturating_sub(1));
        self.backoff_base
            .saturating_mul(factor)
            .min(self.backoff_max)
    }
}

impl Default for CodePolicy {
    fn default() -> Self {
        Self::from_config(&AttendedConfig::default())
    }
}

/// Why a pairing attempt cannot start right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairingUnavailable {
    /// Another pairing attempt is in progress.
    Busy,
    /// Waiting out the backoff after recent failures.
    BackingOff,
}

/// The Agent's current session code and its attempt accounting.
///
/// At most one pairing attempt runs at a time, so parallel connections
/// cannot multiply the guesses allowed per code.
#[derive(Debug)]
pub struct PairingCodes {
    policy: CodePolicy,
    state: Mutex<CodeState>,
    display: watch::Sender<SessionCode>,
}

#[derive(Debug)]
struct CodeState {
    code: SessionCode,
    issued: Instant,
    attempts: u8,
    consecutive_failures: u32,
    not_before: Instant,
    in_progress: bool,
}

impl PairingCodes {
    /// Creates the manager with a fresh code.
    ///
    /// # Errors
    /// [`SessionError::Random`] if the OS generator fails.
    pub fn new(policy: CodePolicy) -> Result<Arc<Self>, SessionError> {
        let code = SessionCode::generate()?;
        let now = Instant::now();
        let (display, _) = watch::channel(code.clone());
        Ok(Arc::new(Self {
            policy,
            state: Mutex::new(CodeState {
                code,
                issued: now,
                attempts: 0,
                consecutive_failures: 0,
                not_before: now,
                in_progress: false,
            }),
            display,
        }))
    }

    /// Follows the code to show; updated on every rotation.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<SessionCode> {
        self.display.subscribe()
    }

    /// Rotates the code whenever it expires. Runs until the task is dropped.
    pub async fn run_expiry(self: Arc<Self>) {
        loop {
            let due = {
                let state = self.lock();
                state.issued.checked_add(self.policy.ttl)
            };
            let Some(due) = due else { return };
            tokio::time::sleep_until(due.into()).await;
            let mut state = self.lock();
            if !state.in_progress && state.issued.elapsed() >= self.policy.ttl {
                self.rotate(&mut state);
            }
        }
    }

    /// Reserves the single pairing slot and counts one attempt.
    pub(crate) fn begin_attempt(self: &Arc<Self>) -> Result<Attempt, PairingUnavailable> {
        let mut state = self.lock();
        if state.in_progress {
            return Err(PairingUnavailable::Busy);
        }
        if Instant::now() < state.not_before {
            return Err(PairingUnavailable::BackingOff);
        }
        if state.issued.elapsed() >= self.policy.ttl {
            self.rotate(&mut state);
        }
        state.in_progress = true;
        state.attempts = state.attempts.saturating_add(1);
        Ok(Attempt {
            codes: Arc::clone(self),
            code: state.code.clone(),
            resolved: false,
        })
    }

    fn finish_attempt(&self, success: bool) {
        let mut state = self.lock();
        state.in_progress = false;
        let now = Instant::now();
        if success {
            state.consecutive_failures = 0;
            state.not_before = now;
            self.rotate(&mut state); // single use
            return;
        }
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        let delay = self.policy.backoff(state.consecutive_failures);
        state.not_before = now.checked_add(delay).unwrap_or(now);
        if state.attempts >= self.policy.max_attempts {
            self.rotate(&mut state);
        }
        tracing::warn!(
            failures = state.consecutive_failures,
            retry_in_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            "pairing attempt failed"
        );
    }

    fn rotate(&self, state: &mut CodeState) {
        match SessionCode::generate() {
            Ok(code) => {
                state.code = code.clone();
                state.issued = Instant::now();
                state.attempts = 0;
                self.display.send_replace(code);
                tracing::info!("session code rotated");
            }
            Err(_) => {
                // Without randomness no safe code exists: exhaust the
                // current one so nothing can pair until the next rotation.
                state.attempts = self.policy.max_attempts;
                state.issued = Instant::now()
                    .checked_sub(self.policy.ttl)
                    .unwrap_or(state.issued);
                tracing::error!("cannot generate a session code: pairing paused");
            }
        }
    }

    fn lock(&self) -> MutexGuard<'_, CodeState> {
        // Every critical section leaves the state consistent before any
        // operation that could panic, so a poisoned lock is still usable.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One reserved pairing attempt. Dropping it without calling
/// [`Attempt::succeed`] counts as a failure, so aborted or timed-out
/// attempts still consume the budget.
#[derive(Debug)]
pub(crate) struct Attempt {
    codes: Arc<PairingCodes>,
    code: SessionCode,
    resolved: bool,
}

impl Attempt {
    fn succeed(mut self) {
        self.resolved = true;
        self.codes.finish_attempt(true);
    }
}

impl Drop for Attempt {
    fn drop(&mut self) {
        if !self.resolved {
            self.codes.finish_attempt(false);
        }
    }
}

/// Both device keys in pairing order.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PairingKeys {
    pub(crate) viewer: DevicePublicKey,
    pub(crate) agent: DevicePublicKey,
}

/// Viewer side of the exchange. Returns once the Agent's MAC verified.
pub(crate) async fn run_viewer(
    ctl: &mut ControlChannel,
    conn: &quinn::Connection,
    code: &SessionCode,
    keys: PairingKeys,
) -> Result<(), SessionError> {
    let (spake, msg_viewer) = Spake2::<Ed25519Group>::start_a(
        &code.password(),
        &Identity::new(SPAKE_ID_VIEWER),
        &Identity::new(SPAKE_ID_AGENT),
    );
    ctl.send(&spake_msg(&msg_viewer)?).await?;
    let ControlMsg::PairingSpake2 { msg: msg_agent } = ctl.recv_active().await? else {
        return Err(SessionError::Protocol("expected PairingSpake2"));
    };
    let shared = Zeroizing::new(
        spake
            .finish(&msg_agent)
            .map_err(|_| SessionError::Protocol("invalid SPAKE2 message"))?,
    );
    let confirm = Confirmation::derive(&shared, &*exporter(conn)?, keys, &msg_viewer, &msg_agent)?;

    ctl.send(&ControlMsg::PairingConfirm {
        mac: confirm.viewer_tag()?,
    })
    .await?;
    match ctl.recv_active().await {
        Ok(ControlMsg::PairingConfirm { mac }) => confirm.check_agent(&mac),
        Ok(_) => Err(SessionError::Protocol("expected PairingConfirm")),
        Err(SessionError::Closed(DisconnectReason::PairingFailed)) => {
            Err(SessionError::PairingFailed)
        }
        Err(err) => Err(err),
    }
}

/// Agent side of the exchange. Consumes `attempt`: success rotates the
/// code, anything else counts as a failed attempt.
pub(crate) async fn run_agent(
    ctl: &mut ControlChannel,
    conn: &quinn::Connection,
    attempt: Attempt,
    keys: PairingKeys,
) -> Result<(), SessionError> {
    let ControlMsg::PairingSpake2 { msg: msg_viewer } = ctl.recv_active().await? else {
        return Err(SessionError::Protocol("expected PairingSpake2"));
    };
    let (spake, msg_agent) = Spake2::<Ed25519Group>::start_b(
        &attempt.code.password(),
        &Identity::new(SPAKE_ID_VIEWER),
        &Identity::new(SPAKE_ID_AGENT),
    );
    let shared = Zeroizing::new(
        spake
            .finish(&msg_viewer)
            .map_err(|_| SessionError::Protocol("invalid SPAKE2 message"))?,
    );
    ctl.send(&spake_msg(&msg_agent)?).await?;
    let confirm = Confirmation::derive(&shared, &*exporter(conn)?, keys, &msg_viewer, &msg_agent)?;

    let ControlMsg::PairingConfirm { mac } = ctl.recv_active().await? else {
        return Err(SessionError::Protocol("expected PairingConfirm"));
    };
    // The Viewer must prove knowledge of the code before the Agent says
    // anything that depends on it.
    confirm.check_viewer(&mac)?;
    attempt.succeed();
    ctl.send(&ControlMsg::PairingConfirm {
        mac: confirm.agent_tag()?,
    })
    .await
}

fn spake_msg(bytes: &[u8]) -> Result<ControlMsg, SessionError> {
    let msg = BoundedBytes::new(bytes.to_vec())
        .map_err(|_| SessionError::Protocol("SPAKE2 message too long"))?;
    Ok(ControlMsg::PairingSpake2 { msg })
}

fn exporter(conn: &quinn::Connection) -> Result<Zeroizing<[u8; 32]>, SessionError> {
    let mut out = Zeroizing::new([0u8; 32]);
    conn.export_keying_material(out.as_mut_slice(), PAIRING_EXPORTER_LABEL, b"")
        .map_err(|_| SessionError::ChannelBinding)?;
    Ok(out)
}

/// Key-confirmation keys bound to the TLS session and both device keys.
struct Confirmation {
    viewer: hmac::Key,
    agent: hmac::Key,
    transcript: digest::Digest,
}

impl Confirmation {
    fn derive(
        shared: &[u8],
        exporter: &[u8; 32],
        keys: PairingKeys,
        msg_viewer: &[u8],
        msg_agent: &[u8],
    ) -> Result<Self, SessionError> {
        let mut transcript = digest::Context::new(&digest::SHA256);
        transcript.update(TRANSCRIPT_DOMAIN);
        transcript.update(keys.viewer.as_bytes());
        transcript.update(keys.agent.as_bytes());
        for msg in [msg_viewer, msg_agent] {
            let len = u32::try_from(msg.len()).map_err(|_| SessionError::PairingFailed)?;
            transcript.update(&len.to_le_bytes());
            transcript.update(msg);
        }
        let transcript = transcript.finish();

        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, exporter).extract(shared);
        let expand = |label: &[u8]| {
            prk.expand(&[label, transcript.as_ref()], hmac::HMAC_SHA256)
                .map(hmac::Key::from)
                .map_err(|_| SessionError::ChannelBinding)
        };
        Ok(Self {
            viewer: expand(VIEWER_CONFIRM_LABEL)?,
            agent: expand(AGENT_CONFIRM_LABEL)?,
            transcript,
        })
    }

    fn tag(key: &hmac::Key, transcript: &digest::Digest) -> Result<[u8; 32], SessionError> {
        <[u8; 32]>::try_from(hmac::sign(key, transcript.as_ref()).as_ref())
            .map_err(|_| SessionError::ChannelBinding)
    }

    fn viewer_tag(&self) -> Result<[u8; 32], SessionError> {
        Self::tag(&self.viewer, &self.transcript)
    }

    fn agent_tag(&self) -> Result<[u8; 32], SessionError> {
        Self::tag(&self.agent, &self.transcript)
    }

    /// Constant-time check of the Viewer's MAC.
    fn check_viewer(&self, mac: &[u8; 32]) -> Result<(), SessionError> {
        hmac::verify(&self.viewer, self.transcript.as_ref(), mac)
            .map_err(|_| SessionError::PairingFailed)
    }

    /// Constant-time check of the Agent's MAC.
    fn check_agent(&self, mac: &[u8; 32]) -> Result<(), SessionError> {
        hmac::verify(&self.agent, self.transcript.as_ref(), mac)
            .map_err(|_| SessionError::PairingFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy(max_attempts: u8) -> CodePolicy {
        CodePolicy {
            ttl: Duration::from_secs(300),
            max_attempts,
            backoff_base: Duration::ZERO,
            backoff_max: Duration::ZERO,
        }
    }

    #[test]
    fn generated_codes_are_six_digits() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let code = SessionCode::generate().unwrap();
            assert_eq!(code.expose().len(), CODE_DIGITS);
            assert!(code.expose().bytes().all(|c| c.is_ascii_digit()));
            seen.insert(code.expose().to_owned());
        }
        assert!(seen.len() > 190, "codes must not repeat often");
    }

    #[test]
    fn parse_accepts_separators_only() {
        for ok in ["123456", "123 456", "123-456", " 1 2 3 4 5 6 "] {
            assert_eq!(SessionCode::parse(ok).unwrap().expose(), "123456");
        }
        for bad in ["", "12345", "1234567", "12345a", "123_456", "１２３４５６"] {
            assert!(SessionCode::parse(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn debug_hides_the_code() {
        let code = SessionCode::parse("424242").unwrap();
        assert!(!format!("{code:?}").contains("4242"));
    }

    #[test]
    fn backoff_doubles_and_caps() {
        let policy = CodePolicy::default();
        assert_eq!(policy.backoff(1), Duration::from_secs(1));
        assert_eq!(policy.backoff(2), Duration::from_secs(2));
        assert_eq!(policy.backoff(4), Duration::from_secs(8));
        assert_eq!(policy.backoff(20), Duration::from_secs(300));
        assert_eq!(policy.backoff(u32::MAX), Duration::from_secs(300));
    }

    #[test]
    fn code_rotates_after_max_failed_attempts() {
        let codes = PairingCodes::new(test_policy(3)).unwrap();
        let display = codes.subscribe();
        let first = display.borrow().clone();
        for _ in 0..2 {
            drop(codes.begin_attempt().unwrap()); // dropped = failed
            assert_eq!(*display.borrow(), first);
        }
        drop(codes.begin_attempt().unwrap());
        assert_ne!(*display.borrow(), first, "third failure must rotate");
    }

    #[test]
    fn success_rotates_the_code() {
        let codes = PairingCodes::new(test_policy(3)).unwrap();
        let display = codes.subscribe();
        let first = display.borrow().clone();
        codes.begin_attempt().unwrap().succeed();
        assert_ne!(*display.borrow(), first);
    }

    #[test]
    fn only_one_attempt_at_a_time() {
        let codes = PairingCodes::new(test_policy(3)).unwrap();
        let attempt = codes.begin_attempt().unwrap();
        assert_eq!(codes.begin_attempt().unwrap_err(), PairingUnavailable::Busy);
        drop(attempt);
        assert!(codes.begin_attempt().is_ok());
    }

    #[test]
    fn failures_trigger_backoff() {
        let codes = PairingCodes::new(CodePolicy {
            backoff_base: Duration::from_secs(60),
            backoff_max: Duration::from_secs(60),
            ..test_policy(3)
        })
        .unwrap();
        drop(codes.begin_attempt().unwrap());
        assert_eq!(
            codes.begin_attempt().unwrap_err(),
            PairingUnavailable::BackingOff
        );
    }

    #[test]
    fn confirmation_depends_on_every_input() {
        let keys = PairingKeys {
            viewer: DevicePublicKey([1; 32]),
            agent: DevicePublicKey([2; 32]),
        };
        let base = || Confirmation::derive(b"shared", &[9; 32], keys, b"a", b"b").unwrap();
        let tag = base().viewer_tag().unwrap();
        assert!(base().check_viewer(&tag).is_ok());
        assert!(base().check_agent(&tag).is_err(), "roles must differ");

        let variants = [
            Confirmation::derive(b"other", &[9; 32], keys, b"a", b"b"),
            Confirmation::derive(b"shared", &[8; 32], keys, b"a", b"b"),
            Confirmation::derive(
                b"shared",
                &[9; 32],
                PairingKeys {
                    viewer: DevicePublicKey([3; 32]),
                    ..keys
                },
                b"a",
                b"b",
            ),
            Confirmation::derive(b"shared", &[9; 32], keys, b"ab", b""),
        ];
        for variant in variants {
            assert!(variant.unwrap().check_viewer(&tag).is_err());
        }
    }
}
