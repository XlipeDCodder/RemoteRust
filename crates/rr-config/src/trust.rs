//! Trusted devices: the keys pinned through pairing (blueprint v2 §7.2).
//!
//! One file per user lists both directions:
//! - `[[agent]]`: Agents this machine (as Viewer) has paired with, plus the
//!   addresses they announced, used for the path race;
//! - `[[viewer]]`: Viewers allowed to request sessions on this machine.
//!
//! Integrity matters more than secrecy here: whoever can edit this file can
//! add a Viewer key. It lives in the user's private data directory and is
//! written owner-only. Unattended access (M5) keeps its own list in storage
//! owned by the privileged service, never in this file.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use rr_proto::{CandidateAddr, DevicePublicKey};
use serde::{Deserialize, Serialize};

use crate::ConfigError;
use crate::files::{default_data_dir, write_atomic};
use crate::model::{invalid, validate_name};
use crate::store::read_text;

/// File name of the trusted-devices list inside the data directory.
pub const TRUST_FILE_NAME: &str = "trust.toml";

/// Hard limit on the trusted-devices file size, enforced while reading.
pub const MAX_TRUST_FILE_SIZE: u64 = 256 * 1024;

/// Maximum number of devices in each list.
pub const MAX_TRUSTED_DEVICES: usize = 256;

/// Maximum number of addresses remembered per Agent.
pub const MAX_KNOWN_ADDRESSES: usize = 16;

/// An Agent this machine has paired with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnownAgent {
    /// Name the Agent announced at pairing time (sanitized).
    pub name: String,
    /// Pinned Ed25519 key.
    pub key: DevicePublicKey,
    /// Addresses the Agent announced, most recent first.
    #[serde(default)]
    pub addresses: Vec<CandidateAddr>,
    /// Pairing time, seconds since the Unix epoch.
    pub paired_at: u64,
}

/// A Viewer allowed to request sessions on this machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnownViewer {
    /// Name the Viewer announced at pairing time (sanitized).
    pub name: String,
    /// Pinned Ed25519 key.
    pub key: DevicePublicKey,
    /// Pairing time, seconds since the Unix epoch.
    pub paired_at: u64,
}

/// Contents of `trust.toml`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TrustStore {
    /// Paired Agents (`[[agent]]` tables).
    #[serde(rename = "agent", skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<KnownAgent>,
    /// Paired Viewers (`[[viewer]]` tables).
    #[serde(rename = "viewer", skip_serializing_if = "Vec::is_empty")]
    pub viewers: Vec<KnownViewer>,
}

impl TrustStore {
    /// Parses and validates a trust store from TOML text.
    ///
    /// # Errors
    /// [`ConfigError::Parse`] or [`ConfigError::Invalid`].
    pub fn from_toml_str(text: &str) -> Result<Self, ConfigError> {
        let store: Self = toml::from_str(text)?;
        store.validate()?;
        Ok(store)
    }

    /// Validates the store and serializes it to TOML text.
    ///
    /// # Errors
    /// [`ConfigError::Invalid`] if a rule is broken (nothing is serialized).
    pub fn to_toml_string(&self) -> Result<String, ConfigError> {
        self.validate()?;
        Ok(toml::to_string_pretty(self)?)
    }

    /// Checks names, list sizes and key uniqueness.
    ///
    /// # Errors
    /// [`ConfigError::Invalid`] naming the offending list.
    pub fn validate(&self) -> Result<(), ConfigError> {
        check_list(
            "agent",
            self.agents.iter().map(|a| (a.name.as_str(), &a.key)),
        )?;
        for agent in &self.agents {
            if agent.addresses.len() > MAX_KNOWN_ADDRESSES {
                return Err(invalid(
                    "agent.addresses",
                    format!("at most {MAX_KNOWN_ADDRESSES} addresses per device"),
                ));
            }
        }
        check_list(
            "viewer",
            self.viewers.iter().map(|v| (v.name.as_str(), &v.key)),
        )
    }

    /// The paired Agent with `key`, if any.
    #[must_use]
    pub fn agent(&self, key: &DevicePublicKey) -> Option<&KnownAgent> {
        self.agents.iter().find(|a| a.key == *key)
    }

    /// The paired Viewer with `key`, if any.
    #[must_use]
    pub fn viewer(&self, key: &DevicePublicKey) -> Option<&KnownViewer> {
        self.viewers.iter().find(|v| v.key == *key)
    }

    /// Adds `agent`, or replaces the entry with the same key in place.
    ///
    /// # Errors
    /// [`ConfigError::Invalid`] if the list is full or the entry is invalid.
    pub fn upsert_agent(&mut self, agent: KnownAgent) -> Result<(), ConfigError> {
        validate_name("agent.name", &agent.name)?;
        upsert(&mut self.agents, agent, "agent", |a| a.key)
    }

    /// Adds `viewer`, or replaces the entry with the same key in place.
    ///
    /// # Errors
    /// [`ConfigError::Invalid`] if the list is full or the entry is invalid.
    pub fn upsert_viewer(&mut self, viewer: KnownViewer) -> Result<(), ConfigError> {
        validate_name("viewer.name", &viewer.name)?;
        upsert(&mut self.viewers, viewer, "viewer", |v| v.key)
    }

    /// Paired Agents matching `query`: a name (case-insensitive) or a key
    /// prefix of at least 8 hex characters.
    #[must_use]
    pub fn find_agents(&self, query: &str) -> Vec<&KnownAgent> {
        self.agents
            .iter()
            .filter(|a| matches_query(&a.name, &a.key, query))
            .collect()
    }

    /// Paired Viewers matching `query`, with the rules of
    /// [`TrustStore::find_agents`].
    #[must_use]
    pub fn find_viewers(&self, query: &str) -> Vec<&KnownViewer> {
        self.viewers
            .iter()
            .filter(|v| matches_query(&v.name, &v.key, query))
            .collect()
    }

    /// Forgets the Agent with `key`. Returns whether it was present.
    pub fn remove_agent(&mut self, key: &DevicePublicKey) -> bool {
        let before = self.agents.len();
        self.agents.retain(|a| a.key != *key);
        self.agents.len() != before
    }

    /// Forgets the Viewer with `key`. Returns whether it was present.
    pub fn remove_viewer(&mut self, key: &DevicePublicKey) -> bool {
        let before = self.viewers.len();
        self.viewers.retain(|v| v.key != *key);
        self.viewers.len() != before
    }
}

/// Shortest key prefix accepted as a lookup, so a stray digit never matches.
const MIN_KEY_PREFIX: usize = 8;

fn matches_query(name: &str, key: &DevicePublicKey, query: &str) -> bool {
    let query = query.trim();
    if name.eq_ignore_ascii_case(query) {
        return true;
    }
    query.len() >= MIN_KEY_PREFIX
        && query.bytes().all(|c| c.is_ascii_hexdigit())
        && key.to_string().starts_with(&query.to_ascii_lowercase())
}

fn check_list<'a>(
    field: &'static str,
    entries: impl ExactSizeIterator<Item = (&'a str, &'a DevicePublicKey)>,
) -> Result<(), ConfigError> {
    if entries.len() > MAX_TRUSTED_DEVICES {
        return Err(invalid(
            field,
            format!("at most {MAX_TRUSTED_DEVICES} devices are allowed"),
        ));
    }
    let mut keys = BTreeSet::new();
    for (name, key) in entries {
        validate_name(field, name)?;
        if !keys.insert(*key) {
            return Err(invalid(
                field,
                format!("key {key} is listed more than once"),
            ));
        }
    }
    Ok(())
}

fn upsert<T>(
    list: &mut Vec<T>,
    entry: T,
    field: &'static str,
    key_of: impl Fn(&T) -> DevicePublicKey,
) -> Result<(), ConfigError> {
    let key = key_of(&entry);
    if let Some(slot) = list.iter_mut().find(|existing| key_of(existing) == key) {
        *slot = entry;
        return Ok(());
    }
    if list.len() >= MAX_TRUSTED_DEVICES {
        return Err(invalid(
            field,
            format!("at most {MAX_TRUSTED_DEVICES} devices are allowed"),
        ));
    }
    list.push(entry);
    Ok(())
}

/// Location of `trust.toml` in the per-user data directory.
#[must_use]
pub fn default_trust_path() -> Option<PathBuf> {
    default_data_dir().map(|dir| dir.join(TRUST_FILE_NAME))
}

/// Reads and validates the trust store at `path`.
///
/// # Errors
/// [`ConfigError::Io`] (including a missing file), [`ConfigError::TooLarge`],
/// or any parse/validation error.
pub fn load_trust(path: &Path) -> Result<TrustStore, ConfigError> {
    let text = read_text(path, MAX_TRUST_FILE_SIZE)?;
    TrustStore::from_toml_str(&text)
}

/// Like [`load_trust`], but returns an empty store when the file does not
/// exist yet.
///
/// # Errors
/// Same as [`load_trust`], except for a missing file.
pub fn load_trust_or_default(path: &Path) -> Result<TrustStore, ConfigError> {
    match load_trust(path) {
        Err(err) if err.is_not_found() => Ok(TrustStore::default()),
        other => other,
    }
}

/// Validates `store` and writes it to `path` atomically, owner-only.
///
/// # Errors
/// [`ConfigError::Invalid`] (nothing is written) or [`ConfigError::Io`].
pub fn save_trust(path: &Path, store: &TrustStore) -> Result<(), ConfigError> {
    let text = store.to_toml_string()?;
    write_atomic(path, text.as_bytes())
}

#[cfg(test)]
mod tests {
    use rr_proto::NetworkClass;

    use super::*;

    fn key(byte: u8) -> DevicePublicKey {
        DevicePublicKey([byte; 32])
    }

    fn agent(byte: u8, name: &str) -> KnownAgent {
        KnownAgent {
            name: name.to_owned(),
            key: key(byte),
            addresses: vec![CandidateAddr {
                class: NetworkClass::Tailscale,
                addr: "100.101.102.103:7878".parse().unwrap(),
            }],
            paired_at: 1_700_000_000,
        }
    }

    fn viewer(byte: u8, name: &str) -> KnownViewer {
        KnownViewer {
            name: name.to_owned(),
            key: key(byte),
            paired_at: 1_700_000_000,
        }
    }

    #[test]
    fn empty_store_round_trips() {
        let store = TrustStore::default();
        assert_eq!(store.to_toml_string().unwrap(), "");
        assert_eq!(TrustStore::from_toml_str("").unwrap(), store);
    }

    #[test]
    fn full_store_round_trips_through_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(TRUST_FILE_NAME);
        let mut store = TrustStore::default();
        store.upsert_agent(agent(1, "office")).unwrap();
        store.upsert_viewer(viewer(2, "laptop")).unwrap();
        save_trust(&path, &store).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("[[agent]]") && text.contains("[[viewer]]"));
        assert_eq!(load_trust(&path).unwrap(), store);
    }

    #[test]
    fn missing_file_is_empty_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(TRUST_FILE_NAME);
        assert!(load_trust(&path).is_err());
        assert_eq!(load_trust_or_default(&path).unwrap(), TrustStore::default());
    }

    #[test]
    fn upsert_replaces_and_remove_forgets() {
        let mut store = TrustStore::default();
        store.upsert_agent(agent(1, "old-name")).unwrap();
        store.upsert_agent(agent(1, "new-name")).unwrap();
        assert_eq!(store.agents.len(), 1);
        assert_eq!(store.agent(&key(1)).unwrap().name, "new-name");

        assert!(store.remove_agent(&key(1)));
        assert!(!store.remove_agent(&key(1)));
        assert!(store.agent(&key(1)).is_none());
    }

    #[test]
    fn lookup_by_name_or_key_prefix() {
        let mut store = TrustStore::default();
        store.upsert_agent(agent(0xAB, "Office-PC")).unwrap();
        store.upsert_agent(agent(0xCD, "laptop")).unwrap();

        assert_eq!(store.find_agents("office-pc").len(), 1);
        assert_eq!(store.find_agents("abababab").len(), 1);
        assert_eq!(store.find_agents("ABABABAB")[0].name, "Office-PC");
        assert!(store.find_agents("abab").is_empty(), "prefix too short");
        assert!(store.find_agents("nobody").is_empty());
        assert!(store.find_viewers("laptop").is_empty());
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        let store = TrustStore {
            viewers: vec![viewer(3, "a"), viewer(3, "b")],
            ..TrustStore::default()
        };
        assert!(matches!(
            store.validate(),
            Err(ConfigError::Invalid {
                field: "viewer",
                ..
            })
        ));
    }

    #[test]
    fn same_key_may_be_agent_and_viewer() {
        let store = TrustStore {
            agents: vec![agent(4, "peer")],
            viewers: vec![viewer(4, "peer")],
        };
        assert!(store.validate().is_ok());
    }

    #[test]
    fn invalid_names_are_rejected() {
        let mut store = TrustStore::default();
        assert!(store.upsert_viewer(viewer(5, "bad\u{0}name")).is_err());
        assert!(store.viewers.is_empty());
    }

    #[test]
    fn lists_are_bounded() {
        let mut store = TrustStore::default();
        for i in 0..MAX_TRUSTED_DEVICES {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&(i as u64).to_le_bytes());
            store
                .upsert_viewer(KnownViewer {
                    key: DevicePublicKey(k),
                    ..viewer(0, "v")
                })
                .unwrap();
        }
        assert!(store.upsert_viewer(viewer(0xFF, "one-too-many")).is_err());
        // Replacing an existing entry still works when full.
        let first = store.viewers[0].key;
        store
            .upsert_viewer(KnownViewer {
                key: first,
                ..viewer(0, "renamed")
            })
            .unwrap();
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let text = format!(
            "[[viewer]]\nname = \"x\"\nkey = \"{}\"\npaired_at = 1\nadmin = true\n",
            key(9)
        );
        assert!(matches!(
            TrustStore::from_toml_str(&text),
            Err(ConfigError::Parse(_))
        ));
    }
}
