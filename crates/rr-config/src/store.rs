//! Reading and writing the configuration file.

use std::io;
use std::path::{Path, PathBuf};

use crate::files::{read_limited, write_atomic};
use crate::{Config, ConfigError};

/// File name of the per-user configuration.
pub const CONFIG_FILE_NAME: &str = "config.toml";

/// Hard limit on the configuration file size, enforced while reading.
pub const MAX_CONFIG_FILE_SIZE: u64 = 64 * 1024;

/// Per-user, per-machine (non-roaming) location of the configuration file.
///
/// - Windows: `%LOCALAPPDATA%\RustRemote\config\config.toml`
/// - Linux: `$XDG_CONFIG_HOME/rustremote/config.toml` (usually `~/.config`)
///
/// Non-roaming on purpose: network policy is specific to this machine.
/// Returns `None` if the OS reports no home directory.
#[must_use]
pub fn default_config_path() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "RustRemote")
        .map(|dirs| dirs.config_local_dir().join(CONFIG_FILE_NAME))
}

/// Reads and validates the configuration at `path`.
///
/// # Errors
/// [`ConfigError::Io`] if the file cannot be read (including when it does
/// not exist), [`ConfigError::TooLarge`], or any parse/validation error.
pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let text = read_text(path, MAX_CONFIG_FILE_SIZE)?;
    Config::from_toml_str(&text)
}

/// Reads a UTF-8 text file of at most `limit` bytes.
pub(crate) fn read_text(path: &Path, limit: u64) -> Result<String, ConfigError> {
    let bytes = read_limited(path, limit)?;
    String::from_utf8(bytes).map_err(|err| ConfigError::Io {
        path: path.to_path_buf(),
        source: io::Error::new(io::ErrorKind::InvalidData, err),
    })
}

/// Like [`load`], but returns the defaults when the file does not exist yet.
///
/// # Errors
/// Same as [`load`], except for a missing file.
pub fn load_or_default(path: &Path) -> Result<Config, ConfigError> {
    match load(path) {
        Err(err) if err.is_not_found() => Ok(Config::default()),
        other => other,
    }
}

/// Validates `config` and writes it to `path` atomically.
///
/// A temporary file in the same directory is fully written and flushed to
/// disk, then renamed over `path`, so a crash never leaves a truncated
/// configuration behind. Missing parent directories are created.
///
/// # Errors
/// [`ConfigError::Invalid`] (nothing is written) or [`ConfigError::Io`].
pub fn save(path: &Path, config: &Config) -> Result<(), ConfigError> {
    let text = config.to_toml_string()?;
    write_atomic(path, text.as_bytes())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::AgentConfig;

    fn config_with_port(listen_port: u16) -> Config {
        Config {
            agent: AgentConfig {
                listen_port,
                ..AgentConfig::default()
            },
            ..Config::default()
        }
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join(CONFIG_FILE_NAME);

        let config = Config {
            device_name: Some("office-pc".to_owned()),
            ..config_with_port(9100)
        };
        save(&path, &config).unwrap();

        assert_eq!(load(&path).unwrap(), config);
        let entries = fs::read_dir(path.parent().unwrap()).unwrap().count();
        assert_eq!(entries, 1, "no temporary file may be left behind");
    }

    #[test]
    fn save_overwrites_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILE_NAME);

        save(&path, &Config::default()).unwrap();
        save(&path, &config_with_port(9200)).unwrap();

        assert_eq!(load(&path).unwrap().agent.listen_port, 9200);
    }

    #[test]
    fn missing_file_yields_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent.toml");

        assert!(matches!(load(&path), Err(ConfigError::Io { .. })));
        assert_eq!(load_or_default(&path).unwrap(), Config::default());
    }

    #[test]
    fn oversized_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILE_NAME);
        let size = usize::try_from(MAX_CONFIG_FILE_SIZE).unwrap() + 1;
        fs::write(&path, "#".repeat(size)).unwrap();

        assert!(matches!(load(&path), Err(ConfigError::TooLarge { .. })));
        assert!(matches!(
            load_or_default(&path),
            Err(ConfigError::TooLarge { .. })
        ));
    }

    #[test]
    fn invalid_config_is_never_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILE_NAME);

        assert!(matches!(
            save(&path, &config_with_port(0)),
            Err(ConfigError::Invalid { .. })
        ));
        assert!(!path.exists());
    }

    #[test]
    fn default_path_points_to_config_file() {
        if let Some(path) = default_config_path() {
            assert!(path.ends_with(CONFIG_FILE_NAME));
        }
    }
}
