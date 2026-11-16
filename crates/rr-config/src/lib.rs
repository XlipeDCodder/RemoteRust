//! RustRemote configuration: data model, validation and storage
//! (blueprint v2 §5.3, §5.4, §7.2, §7.3).
//!
//! Two per-user files:
//! - `config.toml` covers both roles a machine can play: `[agent]` (this
//!   machine is being accessed) and `[viewer]` (this machine accesses
//!   others);
//! - `trust.toml` lists the devices pinned through pairing.
//!
//! Unattended-access settings are deliberately *not* stored here: they
//! belong to the privileged service and are root/SYSTEM-owned (blueprint v2
//! §7.4, milestone M5).
//!
//! Every value is validated on load and before save. Unknown keys are
//! rejected, so a typo never silently falls back to a default.
#![forbid(unsafe_code)]

mod error;
mod files;
mod model;
mod store;
mod trust;

pub use error::ConfigError;
pub use files::{default_data_dir, read_limited, write_atomic, write_new};
pub use model::{
    AgentConfig, AttendedConfig, Config, MAX_ALLOWED_SOURCES, MAX_DEVICE_NAME_LEN,
    MAX_MANUAL_LISTEN, NetworkClass, NetworkPolicies, NetworkPolicy, ViewerConfig,
    sanitize_device_name,
};
pub use store::{
    CONFIG_FILE_NAME, MAX_CONFIG_FILE_SIZE, default_config_path, load, load_or_default, save,
};
pub use trust::{
    KnownAgent, KnownViewer, MAX_KNOWN_ADDRESSES, MAX_TRUST_FILE_SIZE, MAX_TRUSTED_DEVICES,
    TRUST_FILE_NAME, TrustStore, default_trust_path, load_trust, load_trust_or_default, save_trust,
};
