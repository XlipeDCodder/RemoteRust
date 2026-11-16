//! Filesystem helpers shared by every RustRemote file: bounded reads and
//! atomic, owner-only writes.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::ConfigError;

/// Per-user, per-machine (non-roaming) data directory, holding the device
/// identity and the trusted-devices file.
///
/// - Windows: `%LOCALAPPDATA%\RustRemote\data`
/// - Linux: `$XDG_DATA_HOME/rustremote` (usually `~/.local/share/rustremote`)
///
/// Returns `None` if the OS reports no home directory.
#[must_use]
pub fn default_data_dir() -> Option<PathBuf> {
    directories::ProjectDirs::from("", "", "RustRemote")
        .map(|dirs| dirs.data_local_dir().to_path_buf())
}

/// Reads a whole file, refusing files larger than `limit` bytes.
///
/// At most `limit + 1` bytes are ever read, whatever the file metadata
/// claims. The buffer is allocated once, so no stale copies are left behind
/// by reallocation (relevant for secrets). Keep `limit` small.
///
/// # Errors
/// [`ConfigError::Io`] (including a missing file) or
/// [`ConfigError::TooLarge`].
pub fn read_limited(path: &Path, limit: u64) -> Result<Vec<u8>, ConfigError> {
    let io_err = |source: io::Error| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    };

    let file = File::open(path).map_err(io_err)?;
    let capacity = usize::try_from(limit).unwrap_or(0).saturating_add(1);
    let mut bytes = Vec::with_capacity(capacity);
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(io_err)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(ConfigError::TooLarge {
            path: path.to_path_buf(),
            limit,
        });
    }
    Ok(bytes)
}

/// Writes `bytes` to `path` atomically and creates missing parent folders.
///
/// A temporary file in the same directory is fully written and flushed to
/// disk, then renamed over `path`, so a crash never leaves a truncated file.
/// On Unix the file is created with mode `0600` (owner read/write only).
///
/// # Errors
/// [`ConfigError::Io`].
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ConfigError> {
    let io_err = |source: io::Error| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    };

    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(io_err)?;
    }
    let tmp = temporary_path(path);
    let result = write_and_sync(&tmp, bytes).and_then(|()| fs::rename(&tmp, path));
    if result.is_err() {
        // Best effort: the original error is the one worth reporting.
        let _ = fs::remove_file(&tmp);
    }
    result.map_err(io_err)
}

/// Like [`write_atomic`], but never replaces an existing file.
///
/// Returns `Ok(false)`, writing nothing, if `path` already exists. Two
/// processes racing to create the same file therefore agree on a single
/// winner: the content is published with a hard link, which fails if the
/// target exists.
///
/// # Errors
/// [`ConfigError::Io`], including on filesystems without hard links.
pub fn write_new(path: &Path, bytes: &[u8]) -> Result<bool, ConfigError> {
    let io_err = |source: io::Error| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    };

    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(io_err)?;
    }
    let tmp = temporary_path(path);
    let linked = write_and_sync(&tmp, bytes).and_then(|()| fs::hard_link(&tmp, path));
    // Best effort: the temporary name is never needed after linking.
    let _ = fs::remove_file(&tmp);
    match linked {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(err) => Err(io_err(err)),
    }
}

/// A sibling name unique to this process *and* this call, so concurrent
/// writers (threads or processes) never share a temporary file.
fn temporary_path(path: &Path) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut name = path
        .file_name()
        .map_or_else(|| OsString::from("rustremote"), OsString::from);
    name.push(format!(".tmp-{}-{sequence}", std::process::id()));
    path.with_file_name(name)
}

fn write_and_sync(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_then_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a").join("b.bin");
        write_atomic(&path, b"hello").unwrap();
        assert_eq!(read_limited(&path, 5).unwrap(), b"hello");
        assert!(matches!(
            read_limited(&path, 4),
            Err(ConfigError::TooLarge { limit: 4, .. })
        ));
    }

    #[test]
    fn write_new_never_replaces() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x").join("id");
        assert!(write_new(&path, b"first").unwrap());
        assert!(!write_new(&path, b"second").unwrap());
        assert_eq!(fs::read(&path).unwrap(), b"first");
        let entries = fs::read_dir(path.parent().unwrap()).unwrap().count();
        assert_eq!(entries, 1, "no temporary file may be left behind");
    }

    #[cfg(unix)]
    #[test]
    fn files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret");
        write_atomic(&path, b"x").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
