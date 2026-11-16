//! RustRemote configuration: data model, validation and storage
//! (blueprint v2 §5.3, §5.4, §7.3).
//!
//! One TOML file per user covers both roles a machine can play: `[agent]`
//! (this machine is being accessed) and `[viewer]` (this machine accesses
//! others). Unattended-access settings are deliberately *not* stored here:
//! they belong to the privileged service and are root/SYSTEM-owned
//! (blueprint v2 §7.4, milestone M5).
//!
//! Every value is validated on load and before save. Unknown keys are
//! rejected, so a typo never silently falls back to a default.
#![forbid(unsafe_code)]

mod error;
mod model;
mod store;

pub use error::ConfigError;
pub use model::{
    AgentConfig, AttendedConfig, Config, MAX_DEVICE_NAME_LEN, NetworkClass, NetworkPolicies,
    NetworkPolicy, ViewerConfig,
};
pub use store::{
    CONFIG_FILE_NAME, MAX_CONFIG_FILE_SIZE, default_config_path, load, load_or_default, save,
};
