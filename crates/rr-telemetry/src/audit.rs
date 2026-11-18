//! The audit log (blueprint v2 §7.8): connections, pairing, failed
//! attempts, sessions, the kill switch and configuration changes, kept
//! apart from the diagnostic `tracing` output.
//!
//! One JSON object per line in `audit.jsonl`, with a UTC timestamp `ts`
//! and an `event` name first:
//!
//! ```text
//! {"ts":"2026-11-17T14:03:12.512Z","event":"session_accepted","viewer":"laptop",...}
//! ```
//!
//! At [`DEFAULT_MAX_BYTES`] the file is renamed to `audit.1.jsonl`
//! (replacing the previous one) and a new one is started. On Unix only the
//! owner can read it.
//!
//! Same rule as the rest of the code: never record a secret (session codes,
//! private keys, passwords, PAKE messages).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

/// The current audit file's name.
pub const FILE_NAME: &str = "audit.jsonl";
/// The previous audit file's name.
pub const OLD_FILE_NAME: &str = "audit.1.jsonl";
/// Size at which the file is rotated.
pub const DEFAULT_MAX_BYTES: u64 = 1024 * 1024;

/// An append-only audit trail in one directory.
#[derive(Debug)]
pub struct AuditLog {
    path: PathBuf,
    old_path: PathBuf,
    file: File,
    size: u64,
    max_bytes: u64,
}

impl AuditLog {
    /// Opens (or creates) `dir/audit.jsonl`.
    ///
    /// # Errors
    /// I/O errors creating the directory or the file.
    pub fn open(dir: &Path) -> io::Result<Self> {
        Self::with_max_bytes(dir, DEFAULT_MAX_BYTES)
    }

    /// Like [`AuditLog::open`], rotating at `max_bytes`.
    ///
    /// # Errors
    /// I/O errors creating the directory or the file.
    pub fn with_max_bytes(dir: &Path, max_bytes: u64) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let path = dir.join(FILE_NAME);
        let file = open_append(&path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            path,
            old_path: dir.join(OLD_FILE_NAME),
            file,
            size,
            max_bytes,
        })
    }

    /// The current file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends one record. `fields` should be a JSON object; anything else
    /// is stored under `"value"`. Its `ts` and `event` keys, if any, are
    /// replaced.
    ///
    /// # Errors
    /// I/O errors writing or rotating the file.
    pub fn record(&mut self, event: &str, fields: Value) -> io::Result<()> {
        self.record_at(SystemTime::now(), event, fields)
    }

    fn record_at(&mut self, when: SystemTime, event: &str, fields: Value) -> io::Result<()> {
        let mut line = Map::new();
        line.insert("ts".to_owned(), Value::String(rfc3339_utc(when)));
        line.insert("event".to_owned(), Value::String(event.to_owned()));
        match fields {
            Value::Object(fields) => {
                for (key, value) in fields {
                    if key != "ts" && key != "event" {
                        line.insert(key, value);
                    }
                }
            }
            Value::Null => {}
            other => {
                line.insert("value".to_owned(), other);
            }
        }
        let mut bytes = serde_json::to_vec(&Value::Object(line)).map_err(io::Error::other)?;
        bytes.push(b'\n');
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if self.size > 0 && self.size.saturating_add(len) > self.max_bytes {
            self.rotate()?;
        }
        self.file.write_all(&bytes)?;
        self.size = self.size.saturating_add(len);
        Ok(())
    }

    fn rotate(&mut self) -> io::Result<()> {
        // Windows cannot replace a file over an existing one by rename.
        match fs::remove_file(&self.old_path) {
            Err(err) if err.kind() != io::ErrorKind::NotFound => return Err(err),
            _ => {}
        }
        // The handle must not keep the file open across the rename on
        // Windows: swap in the new file first.
        let renamed = self.path.with_extension("jsonl.rotating");
        fs::rename(&self.path, &renamed)?;
        self.file = open_append(&self.path)?;
        self.size = 0;
        fs::rename(&renamed, &self.old_path)
    }
}

fn open_append(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ`.
fn rfc3339_utc(when: SystemTime) -> String {
    let since = when.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = since.as_secs();
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        since.subsec_millis()
    )
}

/// Days since 1970-01-01 to a proleptic Gregorian date (H. Hinnant's
/// `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (
        year,
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::*;

    fn lines(path: &Path) -> Vec<Value> {
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    #[test]
    fn timestamps_are_rfc3339_utc() {
        let at = |secs: u64, millis: u64| {
            rfc3339_utc(UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_millis(millis))
        };
        assert_eq!(at(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(at(951_782_400, 5), "2000-02-29T00:00:00.005Z");
        assert_eq!(at(1_794_927_792, 512), "2026-11-17T15:03:12.512Z");
        assert_eq!(at(4_107_542_399, 999), "2100-02-28T23:59:59.999Z");
    }

    #[test]
    fn records_are_json_lines() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = AuditLog::open(dir.path()).unwrap();
        log.record(
            "session_accepted",
            json!({ "viewer": "laptop \"x\"\nnext", "permissions": "view|control", "event": "spoofed" }),
        )
        .unwrap();
        log.record("agent_started", Value::Null).unwrap();
        drop(log);
        // Appends after reopening.
        let mut log = AuditLog::open(dir.path()).unwrap();
        log.record("kill_switch", json!(7)).unwrap();

        let records = lines(&dir.path().join(FILE_NAME));
        assert_eq!(records.len(), 3);
        assert_eq!(records[0]["event"], "session_accepted");
        assert_eq!(records[0]["viewer"], "laptop \"x\"\nnext");
        assert!(records[0]["ts"].as_str().unwrap().ends_with('Z'));
        assert_eq!(records[1]["event"], "agent_started");
        assert_eq!(records[2]["value"], 7);
        // One record per line, whatever the field contents.
        let text = fs::read_to_string(log.path()).unwrap();
        assert_eq!(text.lines().count(), 3);
    }

    #[test]
    fn rotates_at_the_size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = AuditLog::with_max_bytes(dir.path(), 300).unwrap();
        for n in 0..10 {
            log.record("tick", json!({ "n": n, "pad": "x".repeat(40) }))
                .unwrap();
        }
        let current = lines(&dir.path().join(FILE_NAME));
        let old = lines(&dir.path().join(OLD_FILE_NAME));
        assert!(fs::metadata(dir.path().join(FILE_NAME)).unwrap().len() <= 300);
        assert!(!old.is_empty());
        // Nothing is lost between the two newest files, in order.
        let numbers: Vec<_> = old.iter().chain(&current).map(|r| r["n"].clone()).collect();
        let last = numbers.last().unwrap().as_u64().unwrap();
        assert_eq!(last, 9);
        let first = numbers[0].as_u64().unwrap();
        let expected: Vec<_> = (first..=9).map(|n| json!(n)).collect();
        assert_eq!(numbers, expected);
        assert!(!dir.path().join("audit.jsonl.rotating").exists());
    }

    #[cfg(unix)]
    #[test]
    fn only_the_owner_can_read_it() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let log = AuditLog::open(dir.path()).unwrap();
        let mode = fs::metadata(log.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
