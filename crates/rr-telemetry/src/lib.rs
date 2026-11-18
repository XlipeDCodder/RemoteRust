//! Logging setup shared by every RustRemote binary (blueprint v2 §7.8, §8.10),
//! and the audit log ([`audit`]).
//!
//! Verbosity comes from the `RUSTREMOTE_LOG` environment variable, using
//! `tracing` filter syntax (for example `debug` or `rr_net=trace,info`).
//! The default is `info`.
//!
//! Rule for every crate: secrets (private keys, session codes, passwords,
//! SPAKE2/OPAQUE messages) must never be logged, at any level.
#![forbid(unsafe_code)]

use std::io::IsTerminal as _;

use tracing_subscriber::EnvFilter;

pub mod audit;

pub use audit::AuditLog;

/// Environment variable holding the log filter.
pub const LOG_ENV_VAR: &str = "RUSTREMOTE_LOG";

/// Filter used when `RUSTREMOTE_LOG` is unset or invalid.
pub const DEFAULT_FILTER: &str = "info";

/// Errors returned by [`init`].
#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    /// A global `tracing` subscriber was already installed.
    #[error("logging was already initialized")]
    AlreadyInitialized,
}

/// Installs the global `tracing` subscriber (human-readable output on stderr).
///
/// An invalid `RUSTREMOTE_LOG` value does not abort the program: the default
/// filter is used and a warning is logged.
///
/// # Errors
/// [`TelemetryError::AlreadyInitialized`] if called more than once.
pub fn init() -> Result<(), TelemetryError> {
    let requested = std::env::var(LOG_ENV_VAR).ok();
    let (filter, rejected) = match requested.as_deref().map(EnvFilter::try_new) {
        None => (EnvFilter::new(DEFAULT_FILTER), None),
        Some(Ok(filter)) => (filter, None),
        Some(Err(err)) => (EnvFilter::new(DEFAULT_FILTER), Some(err)),
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .try_init()
        .map_err(|_| TelemetryError::AlreadyInitialized)?;

    if let Some(err) = rejected {
        tracing::warn!(%err, "invalid {LOG_ENV_VAR} value; using `{DEFAULT_FILTER}`");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_init_is_rejected() {
        init().unwrap();
        assert!(matches!(init(), Err(TelemetryError::AlreadyInitialized)));
    }
}
