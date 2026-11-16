//! RustRemote Agent: runs on the machine being accessed (blueprint v2 §4.1).
//!
//! Unprivileged process: network endpoint, protocol parsing, capture,
//! encoding, input injection (attended mode), tray icon and consent dialog.
#![forbid(unsafe_code)]

use anyhow::Context as _;

fn main() -> anyhow::Result<()> {
    rr_telemetry::init()?;

    let path =
        rr_config::default_config_path().context("cannot determine the configuration directory")?;
    let config = rr_config::load_or_default(&path)
        .with_context(|| format!("cannot load {}", path.display()))?;

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %path.display(),
        listen_port = config.agent.listen_port,
        "rr-agent starting"
    );
    tracing::warn!("networking is not implemented yet (milestone M1)");
    Ok(())
}
