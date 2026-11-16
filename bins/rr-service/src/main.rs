//! RustRemote privileged service, installed only for unattended access
//! (blueprint v2 §4.1, §7.4).
//!
//! Runs as `LocalSystem` (Windows Service) or `root` (systemd unit). It never
//! opens a network socket: it owns the machine identity and the unattended
//! configuration, and spawns `rr-desktop-helper` and `rr-agent` in the active
//! session.
#![forbid(unsafe_code)]

fn main() -> anyhow::Result<()> {
    rr_telemetry::init()?;
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "rr-service starting");
    tracing::warn!("the privileged service is not implemented yet (milestone M5)");
    Ok(())
}
