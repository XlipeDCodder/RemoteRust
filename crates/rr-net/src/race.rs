//! Viewer path selection: filter, order and race candidate addresses
//! (blueprint v2 §5.4, Happy-Eyeballs style per RFC 8305).

use std::collections::{BTreeSet, HashSet};
use std::future::Future;
use std::time::Duration;

use rr_proto::{CandidateAddr, NetworkClass};
use tokio::task::JoinSet;

use crate::SessionError;

/// Why no path could be established.
#[derive(Debug, thiserror::Error)]
pub enum RaceError {
    /// Nothing to try: no candidate matches the priority list and the
    /// VPNs that are up on this machine.
    #[error("no usable address for this Agent (check `viewer.network_priority` and VPN status)")]
    NoCandidates,
    /// Every attempt failed; one entry per candidate.
    #[error("every path to the Agent failed ({} attempts)", .0.len())]
    AllFailed(Vec<(CandidateAddr, SessionError)>),
}

/// Classes reachable only through a local adapter of the same class.
/// LAN and manual addresses may be routed through anything (for example a
/// corporate LAN reached through FortiClient), so they are always tried.
const fn needs_local_adapter(class: NetworkClass) -> bool {
    matches!(
        class,
        NetworkClass::Tailscale | NetworkClass::Radmin | NetworkClass::FortiClient
    )
}

/// Keeps the candidates worth trying, in priority order, without
/// duplicates. Within a class the stored order is kept.
#[must_use]
pub fn order_candidates(
    candidates: &[CandidateAddr],
    priority: &[NetworkClass],
    local_classes: &BTreeSet<NetworkClass>,
) -> Vec<CandidateAddr> {
    let mut seen = HashSet::new();
    priority
        .iter()
        .filter(|class| !needs_local_adapter(**class) || local_classes.contains(class))
        .flat_map(|class| candidates.iter().filter(move |c| c.class == *class))
        .filter(|candidate| seen.insert(candidate.addr))
        .copied()
        .collect()
}

/// Starts `attempt` for each candidate, `stagger` apart, and returns the
/// first success. The other attempts are cancelled; their connections are
/// dropped, which closes them.
///
/// # Errors
/// [`RaceError::NoCandidates`] or [`RaceError::AllFailed`].
pub async fn race<T, F, Fut>(
    candidates: Vec<CandidateAddr>,
    stagger: Duration,
    attempt: F,
) -> Result<(CandidateAddr, T), RaceError>
where
    T: Send + 'static,
    F: Fn(CandidateAddr) -> Fut,
    Fut: Future<Output = Result<T, SessionError>> + Send + 'static,
{
    if candidates.is_empty() {
        return Err(RaceError::NoCandidates);
    }
    let mut attempts = JoinSet::new();
    for (index, candidate) in candidates.into_iter().enumerate() {
        let delay = stagger.saturating_mul(u32::try_from(index).unwrap_or(u32::MAX));
        // Not polled before the delay, so nothing is sent early.
        let connect = attempt(candidate);
        attempts.spawn(async move {
            tokio::time::sleep(delay).await;
            (candidate, connect.await)
        });
    }

    let mut failures = Vec::new();
    while let Some(joined) = attempts.join_next().await {
        match joined {
            Ok((candidate, Ok(value))) => {
                tracing::debug!(%candidate, "path won the race");
                attempts.abort_all();
                return Ok((candidate, value));
            }
            Ok((candidate, Err(err))) => {
                tracing::debug!(%candidate, error = %err, "path failed");
                failures.push((candidate, err));
            }
            Err(err) => tracing::warn!(error = %err, "connection attempt task failed"),
        }
    }
    Err(RaceError::AllFailed(failures))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(class: NetworkClass, addr: &str) -> CandidateAddr {
        CandidateAddr {
            class,
            addr: addr.parse().unwrap(),
        }
    }

    #[test]
    fn order_filters_and_sorts() {
        let candidates = [
            cand(NetworkClass::Lan, "192.168.1.10:7878"),
            cand(NetworkClass::Radmin, "26.1.2.3:7878"),
            cand(NetworkClass::Tailscale, "100.101.1.2:7878"),
            cand(NetworkClass::Tailscale, "[fd7a:115c:a1e0::5]:7878"),
            cand(NetworkClass::Manual, "192.168.1.10:7878"), // duplicate address
        ];
        let local = BTreeSet::from([NetworkClass::Tailscale]);
        let ordered = order_candidates(&candidates, &NetworkClass::ALL, &local);
        assert_eq!(
            ordered,
            [
                cand(NetworkClass::Tailscale, "100.101.1.2:7878"),
                cand(NetworkClass::Tailscale, "[fd7a:115c:a1e0::5]:7878"),
                cand(NetworkClass::Lan, "192.168.1.10:7878"),
            ],
            "Radmin needs a local Radmin adapter; duplicates are dropped"
        );
    }

    #[test]
    fn priority_list_controls_order_and_membership() {
        let candidates = [
            cand(NetworkClass::Tailscale, "100.101.1.2:7878"),
            cand(NetworkClass::Lan, "192.168.1.10:7878"),
        ];
        let local = BTreeSet::from([NetworkClass::Tailscale]);
        let ordered = order_candidates(&candidates, &[NetworkClass::Lan], &local);
        assert_eq!(ordered, [cand(NetworkClass::Lan, "192.168.1.10:7878")]);
    }

    #[tokio::test]
    async fn first_success_wins_even_if_later_in_order() {
        let candidates = vec![
            cand(NetworkClass::Tailscale, "100.101.1.2:7878"),
            cand(NetworkClass::Lan, "192.168.1.10:7878"),
        ];
        let tailscale = candidates[0].addr;
        let (winner, value) = race(candidates, Duration::from_millis(10), move |c| async move {
            if c.addr == tailscale {
                // Slow path: still connecting when the other one succeeds.
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
            Ok::<_, SessionError>(c.addr.port())
        })
        .await
        .unwrap();
        assert_eq!(winner.class, NetworkClass::Lan);
        assert_eq!(value, 7878);
    }

    #[tokio::test]
    async fn all_failures_are_reported() {
        let candidates = vec![
            cand(NetworkClass::Tailscale, "100.101.1.2:7878"),
            cand(NetworkClass::Lan, "192.168.1.10:7878"),
        ];
        let err = race(candidates, Duration::ZERO, |_| async {
            Err::<(), _>(SessionError::Timeout)
        })
        .await
        .unwrap_err();
        assert!(
            matches!(err, RaceError::AllFailed(ref f) if f.len() == 2),
            "{err:?}"
        );
        assert!(matches!(
            race(Vec::new(), Duration::ZERO, |_| async {
                Ok::<_, SessionError>(())
            })
            .await,
            Err(RaceError::NoCandidates)
        ));
    }
}
