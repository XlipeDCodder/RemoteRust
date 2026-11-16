//! Error type for the configuration crate.

use std::path::PathBuf;

/// Errors produced while loading, validating or saving the configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The configuration file could not be read or written.
    #[error("I/O error on {}", .path.display())]
    Io {
        /// File involved in the failed operation.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// The file is larger than [`crate::MAX_CONFIG_FILE_SIZE`].
    #[error("{} is larger than the {limit}-byte limit", .path.display())]
    TooLarge {
        /// Offending file.
        path: PathBuf,
        /// Maximum accepted size, in bytes.
        limit: u64,
    },

    /// The text is not valid TOML or does not match the schema
    /// (unknown key, wrong type, unknown network class...).
    #[error("invalid configuration file")]
    Parse(#[from] toml::de::Error),

    /// The configuration could not be serialized to TOML.
    #[error("could not serialize the configuration")]
    Serialize(#[from] toml::ser::Error),

    /// A value is well-formed but breaks a rule.
    #[error("invalid value for `{field}`: {reason}")]
    Invalid {
        /// Dotted path of the offending key, e.g. `agent.listen_port`.
        field: &'static str,
        /// Human-readable explanation.
        reason: String,
    },
}
