//! RustRemote Viewer: the app used to control a remote Agent
//! (blueprint v2 §4.1).
//!
//! Unprivileged process: UI, path selection, decoding, rendering and local
//! input capture.
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
        network_priority = ?config.viewer.network_priority,
        "rr-viewer starting"
    );
    tracing::warn!("connecting is not implemented yet (milestone M1)");
    Ok(())
}
