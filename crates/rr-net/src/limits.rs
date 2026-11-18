//! Failure budgets against online guessing and connection floods
//! (blueprint v2 §7.5).
//!
//! Three separate budgets:
//! - **Per source IP.** Every failure before authentication (an unknown
//!   key rejected during TLS, a wrong session code, a timeout, garbage)
//!   blocks that address for 1 s, 2 s, 4 s… up to 5 min. A successful
//!   login from the address clears it.
//! - **Per device key.** Only paired devices get this far: a screen request
//!   the local user denied or left unanswered makes the same device wait
//!   before it may ask again, so nobody can flood the owner with prompts.
//!   Strangers' failures never touch it, so they cannot lock the owner out.
//! - **Global.** Ten failures within an hour, from anywhere, suspend
//!   pairing of new devices for an hour; paired devices are unaffected.
//!
//! Memory is bounded: at most [`MAX_TRACKED`] addresses and keys each.
//! The limiter is a plain state machine; callers pass the current time.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use rr_proto::DevicePublicKey;

/// Addresses (and, separately, keys) remembered at most.
pub const MAX_TRACKED: usize = 4096;

/// Budget parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitPolicy {
    /// Wait after the first failure; doubles with each further one.
    pub backoff_base: Duration,
    /// Longest wait.
    pub backoff_max: Duration,
    /// A record with no failure for this long is forgotten.
    pub forget_after: Duration,
    /// Failures counted for the global budget within this window...
    pub global_window: Duration,
    /// ...that suspend pairing when reached...
    pub global_threshold: usize,
    /// ...for this long.
    pub pairing_suspension: Duration,
}

impl Default for LimitPolicy {
    fn default() -> Self {
        Self {
            backoff_base: Duration::from_secs(1),
            backoff_max: Duration::from_secs(300),
            forget_after: Duration::from_secs(600),
            global_window: Duration::from_secs(3600),
            global_threshold: 10,
            pairing_suspension: Duration::from_secs(3600),
        }
    }
}

impl LimitPolicy {
    /// No waits and no suspension: for tests of everything else.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            backoff_base: Duration::ZERO,
            backoff_max: Duration::ZERO,
            forget_after: Duration::ZERO,
            global_window: Duration::ZERO,
            global_threshold: usize::MAX,
            pairing_suspension: Duration::ZERO,
        }
    }

    /// The wait after `failures` consecutive failures (at least one).
    #[must_use]
    pub fn backoff(&self, failures: u32) -> Duration {
        let doublings = failures.saturating_sub(1).min(31);
        self.backoff_base
            .saturating_mul(1_u32 << doublings)
            .min(self.backoff_max)
    }
}

/// Why a connection attempt counted as a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailureKind {
    /// The TLS handshake rejected the peer's key (unknown device while
    /// pairing is closed) or failed otherwise.
    Handshake,
    /// TLS plus authentication did not finish in time.
    Timeout,
    /// A Viewer asked to connect without being paired.
    NotPaired,
    /// A pairing attempt while pairing was unavailable.
    PairingUnavailable,
    /// A wrong session code (or a tampered pairing).
    WrongCode,
    /// Malformed or unexpected messages.
    Protocol,
}

impl FailureKind {
    /// Short machine-readable name, for logs and the audit trail.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Handshake => "handshake",
            Self::Timeout => "timeout",
            Self::NotPaired => "not_paired",
            Self::PairingUnavailable => "pairing_unavailable",
            Self::WrongCode => "wrong_code",
            Self::Protocol => "protocol",
        }
    }
}

impl std::fmt::Display for FailureKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What recording an address failure led to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailureOutcome {
    /// How long the address is now blocked.
    pub blocked_for: Duration,
    /// `Some` when this failure suspended pairing: for how long.
    pub pairing_suspended_for: Option<Duration>,
}

/// One address's or key's recent failures.
#[derive(Debug, Clone, Copy)]
struct Record {
    failures: u32,
    blocked_until: Instant,
    last_failure: Instant,
    /// The current block was already reported (see [`Blocked::first`]).
    reported: bool,
}

/// A refusal because of an active block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Blocked {
    /// Time left.
    pub remaining: Duration,
    /// Whether this is the first refusal of the current block, so it is
    /// reported once rather than once per packet.
    pub first: bool,
}

/// Failures keyed by something (an address or a device key).
#[derive(Debug)]
struct Budget<K> {
    records: HashMap<K, Record>,
}

impl<K: Eq + Hash + Copy> Budget<K> {
    fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }

    fn blocked(&mut self, key: &K, now: Instant) -> Option<Blocked> {
        let record = self.records.get_mut(key)?;
        let remaining = record.blocked_until.checked_duration_since(now)?;
        if remaining.is_zero() {
            return None;
        }
        let first = !record.reported;
        record.reported = true;
        Some(Blocked { remaining, first })
    }

    fn fail(&mut self, key: K, now: Instant, policy: &LimitPolicy) -> Duration {
        if !self.records.contains_key(&key) && self.records.len() >= MAX_TRACKED {
            self.make_room(now, policy);
        }
        let record = self.records.entry(key).or_insert(Record {
            failures: 0,
            blocked_until: now,
            last_failure: now,
            reported: false,
        });
        if now.saturating_duration_since(record.last_failure) >= policy.forget_after {
            record.failures = 0;
        }
        record.failures = record.failures.saturating_add(1);
        record.last_failure = now;
        record.reported = false;
        let wait = policy.backoff(record.failures);
        record.blocked_until = now.checked_add(wait).unwrap_or(now);
        wait
    }

    fn clear(&mut self, key: &K) {
        self.records.remove(key);
    }

    /// Drops forgotten records; if none, the one with the oldest failure.
    fn make_room(&mut self, now: Instant, policy: &LimitPolicy) {
        let before = self.records.len();
        self.records.retain(|_, record| {
            now.saturating_duration_since(record.last_failure) < policy.forget_after
                || record.blocked_until > now
        });
        if self.records.len() < before {
            return;
        }
        let oldest = self
            .records
            .iter()
            .min_by_key(|(_, record)| record.last_failure)
            .map(|(key, _)| *key);
        if let Some(key) = oldest {
            self.records.remove(&key);
        }
    }

    fn len(&self) -> usize {
        self.records.len()
    }
}

/// The three failure budgets of one Agent.
#[derive(Debug)]
pub struct FailureLimiter {
    policy: LimitPolicy,
    addresses: Budget<IpAddr>,
    keys: Budget<DevicePublicKey>,
    /// Recent failures for the global budget, oldest first.
    recent: VecDeque<Instant>,
    pairing_suspended_until: Option<Instant>,
}

impl FailureLimiter {
    /// An empty limiter.
    #[must_use]
    pub fn new(policy: LimitPolicy) -> Self {
        Self {
            policy,
            addresses: Budget::new(),
            keys: Budget::new(),
            recent: VecDeque::new(),
            pairing_suspended_until: None,
        }
    }

    /// The policy in force.
    #[must_use]
    pub const fn policy(&self) -> &LimitPolicy {
        &self.policy
    }

    /// `Some` while `ip` must be refused.
    pub fn address_blocked(&mut self, ip: IpAddr, now: Instant) -> Option<Blocked> {
        self.addresses.blocked(&ip.to_canonical(), now)
    }

    /// Records a failed attempt from `ip`.
    pub fn address_failed(&mut self, ip: IpAddr, now: Instant) -> FailureOutcome {
        let blocked_for = self.addresses.fail(ip.to_canonical(), now, &self.policy);
        FailureOutcome {
            blocked_for,
            pairing_suspended_for: self.count_global(now),
        }
    }

    /// A successful login from `ip`: its failures are forgiven.
    pub fn address_succeeded(&mut self, ip: IpAddr) {
        self.addresses.clear(&ip.to_canonical());
    }

    /// `Some` while the paired device `key` must wait before asking again.
    pub fn key_blocked(&mut self, key: &DevicePublicKey, now: Instant) -> Option<Blocked> {
        self.keys.blocked(key, now)
    }

    /// A screen request from `key` was denied or not answered.
    pub fn key_refused(&mut self, key: DevicePublicKey, now: Instant) -> Duration {
        self.keys.fail(key, now, &self.policy)
    }

    /// A screen request from `key` was accepted.
    pub fn key_accepted(&mut self, key: &DevicePublicKey) {
        self.keys.clear(key);
    }

    /// Whether pairing of new devices is suspended at `now`.
    #[must_use]
    pub fn pairing_suspended(&self, now: Instant) -> bool {
        self.pairing_suspended_until
            .is_some_and(|until| until > now)
    }

    /// Adds a failure to the global budget; `Some(duration)` when that
    /// starts a pairing suspension.
    fn count_global(&mut self, now: Instant) -> Option<Duration> {
        while let Some(&oldest) = self.recent.front() {
            if now.saturating_duration_since(oldest) < self.policy.global_window {
                break;
            }
            self.recent.pop_front();
        }
        self.recent.push_back(now);
        // Only the last `threshold` failures matter.
        while self.recent.len() > self.policy.global_threshold.min(MAX_TRACKED) {
            self.recent.pop_front();
        }
        if self.recent.len() < self.policy.global_threshold || self.pairing_suspended(now) {
            return None;
        }
        let suspension = self.policy.pairing_suspension;
        self.pairing_suspended_until = now.checked_add(suspension);
        Some(suspension)
    }

    /// Addresses and keys currently remembered (for tests and status).
    #[must_use]
    pub fn tracked(&self) -> (usize, usize) {
        (self.addresses.len(), self.keys.len())
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)] // MAX_TRACKED (4096) fits a u32
mod tests {
    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    fn key(byte: u8) -> DevicePublicKey {
        DevicePublicKey([byte; 32])
    }

    const S: Duration = Duration::from_secs(1);

    #[test]
    fn backoff_doubles_and_caps() {
        let policy = LimitPolicy::default();
        assert_eq!(policy.backoff(1), S);
        assert_eq!(policy.backoff(2), 2 * S);
        assert_eq!(policy.backoff(4), 8 * S);
        assert_eq!(policy.backoff(9), 256 * S);
        assert_eq!(policy.backoff(10), 300 * S);
        assert_eq!(policy.backoff(u32::MAX), 300 * S);
        assert_eq!(LimitPolicy::disabled().backoff(7), Duration::ZERO);
    }

    #[test]
    fn address_blocks_grow_and_expire() {
        let t0 = Instant::now();
        let mut limiter = FailureLimiter::new(LimitPolicy::default());
        assert_eq!(limiter.address_blocked(ip(1), t0), None);

        assert_eq!(limiter.address_failed(ip(1), t0).blocked_for, S);
        let blocked = limiter.address_blocked(ip(1), t0).unwrap();
        assert_eq!(
            blocked,
            Blocked {
                remaining: S,
                first: true
            }
        );
        // Reported once per block.
        assert!(!limiter.address_blocked(ip(1), t0).unwrap().first);
        // Other addresses are unaffected.
        assert_eq!(limiter.address_blocked(ip(2), t0), None);

        let t1 = t0 + S;
        assert_eq!(limiter.address_blocked(ip(1), t1), None);
        assert_eq!(limiter.address_failed(ip(1), t1).blocked_for, 2 * S);
        assert_eq!(limiter.address_failed(ip(1), t1).blocked_for, 4 * S);
        assert!(limiter.address_blocked(ip(1), t1).unwrap().first);

        // A success forgives.
        limiter.address_succeeded(ip(1));
        assert_eq!(limiter.address_blocked(ip(1), t1), None);
        assert_eq!(limiter.address_failed(ip(1), t1).blocked_for, S);

        // So does a long quiet period.
        let later = t1 + Duration::from_secs(601);
        assert_eq!(limiter.address_failed(ip(1), later).blocked_for, S);
    }

    #[test]
    fn mapped_ipv6_counts_as_ipv4() {
        let t0 = Instant::now();
        let mut limiter = FailureLimiter::new(LimitPolicy::default());
        limiter.address_failed("::ffff:10.0.0.1".parse().unwrap(), t0);
        assert!(limiter.address_blocked(ip(1), t0).is_some());
    }

    #[test]
    fn global_failures_suspend_pairing_once() {
        let t0 = Instant::now();
        let mut limiter = FailureLimiter::new(LimitPolicy::default());
        for n in 0..9 {
            let outcome = limiter.address_failed(ip(n), t0 + n as u32 * S);
            assert_eq!(outcome.pairing_suspended_for, None);
        }
        assert!(!limiter.pairing_suspended(t0 + 9 * S));
        let outcome = limiter.address_failed(ip(9), t0 + 9 * S);
        assert_eq!(
            outcome.pairing_suspended_for,
            Some(Duration::from_secs(3600))
        );
        assert!(limiter.pairing_suspended(t0 + 10 * S));
        // Further failures do not restart the suspension.
        let outcome = limiter.address_failed(ip(10), t0 + 10 * S);
        assert_eq!(outcome.pairing_suspended_for, None);
        assert!(!limiter.pairing_suspended(t0 + 9 * S + Duration::from_secs(3600)));
    }

    #[test]
    fn global_window_slides() {
        let t0 = Instant::now();
        let mut limiter = FailureLimiter::new(LimitPolicy::default());
        // Nine failures, then one more just after the first left the window.
        for n in 0..9 {
            limiter.address_failed(ip(n), t0 + n as u32 * S);
        }
        let outcome = limiter.address_failed(ip(20), t0 + Duration::from_secs(3600));
        assert_eq!(outcome.pairing_suspended_for, None);
    }

    #[test]
    fn keys_have_their_own_budget() {
        let t0 = Instant::now();
        let mut limiter = FailureLimiter::new(LimitPolicy::default());
        // Strangers failing do not block a paired device.
        for n in 0..20 {
            limiter.address_failed(ip(n), t0);
        }
        assert_eq!(limiter.key_blocked(&key(1), t0), None);

        assert_eq!(limiter.key_refused(key(1), t0), S);
        assert_eq!(limiter.key_refused(key(1), t0), 2 * S);
        assert!(limiter.key_blocked(&key(1), t0).is_some());
        assert_eq!(limiter.key_blocked(&key(2), t0), None);
        limiter.key_accepted(&key(1));
        assert_eq!(limiter.key_blocked(&key(1), t0), None);
    }

    #[test]
    fn memory_stays_bounded() {
        let t0 = Instant::now();
        let mut limiter = FailureLimiter::new(LimitPolicy::default());
        for n in 0..(MAX_TRACKED as u32 + 100) {
            let addr = IpAddr::from((0x0A00_0000_u32 + n).to_be_bytes());
            limiter.address_failed(addr, t0 + Duration::from_millis(u64::from(n)));
        }
        assert_eq!(limiter.tracked().0, MAX_TRACKED);
        // The newest is kept, the oldest went first.
        let newest = IpAddr::from((0x0A00_0000_u32 + MAX_TRACKED as u32 + 99).to_be_bytes());
        assert!(limiter.address_blocked(newest, t0).is_some());
        let oldest = IpAddr::from(0x0A00_0000_u32.to_be_bytes());
        assert!(limiter.address_blocked(oldest, t0).is_none());
    }

    #[test]
    fn forgotten_records_make_room_first() {
        let t0 = Instant::now();
        let mut limiter = FailureLimiter::new(LimitPolicy::default());
        for n in 0..MAX_TRACKED as u32 {
            let addr = IpAddr::from((0x0A00_0000_u32 + n).to_be_bytes());
            limiter.address_failed(addr, t0);
        }
        // Long after: every old record is prunable at once.
        let later = t0 + Duration::from_secs(3600);
        limiter.address_failed(IpAddr::from([192, 168, 0, 1]), later);
        assert_eq!(limiter.tracked().0, 1);
    }
}
