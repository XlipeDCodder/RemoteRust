//! RustRemote Desktop Helper (blueprint v2 §4.1).
//!
//! Spawned by `rr-service` in the console session with a SYSTEM/root token.
//! It captures, encodes and injects input on the login screen and the
//! Windows secure desktop. It never touches the network: it only speaks the
//! fixed-schema IPC defined in `rr-ipc`.
#![forbid(unsafe_code)]

fn main() -> anyhow::Result<()> {
    rr_telemetry::init()?;
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        "rr-desktop-helper starting"
    );
    tracing::warn!("the desktop helper is not implemented yet (milestone M5)");
    Ok(())
}
