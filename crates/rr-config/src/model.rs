//! Configuration data model and validation rules.

use std::collections::BTreeSet;
use std::fmt;
use std::ops::RangeInclusive;

use serde::{Deserialize, Serialize};

use crate::ConfigError;

/// Maximum length of a device name, in bytes. Matches the protocol limit for
/// names sent to peers.
pub const MAX_DEVICE_NAME_LEN: usize = 64;

/// Upper bound for [`ViewerConfig::race_stagger_ms`].
const MAX_RACE_STAGGER_MS: u16 = 2_000;

/// Root of the per-user configuration file.
///
/// Missing sections and keys take their default values; unknown keys are
/// rejected.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Name shown to peers. `None` means "use the OS hostname".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    /// Settings used when this machine is accessed.
    pub agent: AgentConfig,
    /// Settings used when this machine accesses others.
    pub viewer: ViewerConfig,
}

impl Config {
    /// Parses and validates a configuration from TOML text.
    ///
    /// # Errors
    /// [`ConfigError::Parse`] for syntax or schema errors,
    /// [`ConfigError::Invalid`] for rule violations.
    pub fn from_toml_str(text: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    /// Validates the configuration and serializes it to TOML text.
    ///
    /// # Errors
    /// [`ConfigError::Invalid`] if a rule is broken (nothing is serialized).
    pub fn to_toml_string(&self) -> Result<String, ConfigError> {
        self.validate()?;
        Ok(toml::to_string_pretty(self)?)
    }

    /// Checks the rules that the type system cannot express.
    ///
    /// # Errors
    /// [`ConfigError::Invalid`] naming the first offending key.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if let Some(name) = &self.device_name {
            validate_device_name(name)?;
        }
        self.agent.validate()?;
        self.viewer.validate()
    }
}

/// Agent role: this machine is being accessed (blueprint v2 §5.3, §7.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentConfig {
    /// UDP port of the QUIC listeners.
    pub listen_port: u16,
    /// Listening and access policy per network class.
    pub networks: NetworkPolicies,
    /// Attended-session parameters.
    pub attended: AttendedConfig,
}

impl AgentConfig {
    /// Default UDP port.
    pub const DEFAULT_PORT: u16 = 7878;

    fn validate(&self) -> Result<(), ConfigError> {
        if self.listen_port == 0 {
            return Err(invalid("agent.listen_port", "must be between 1 and 65535"));
        }
        for class in NetworkClass::ALL {
            let policy = self.networks.get(class);
            if (policy.attended || policy.unattended) && !policy.listen {
                return Err(invalid(
                    "agent.networks",
                    format!("`{class}` accepts sessions but has `listen = false`"),
                ));
            }
        }
        self.attended.validate()
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            listen_port: Self::DEFAULT_PORT,
            networks: NetworkPolicies::default(),
            attended: AttendedConfig::default(),
        }
    }
}

/// Network classes RustRemote can detect (blueprint v2 §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkClass {
    /// Tailscale (WireGuard).
    Tailscale,
    /// Radmin VPN (Windows only).
    Radmin,
    /// FortiClient SSL-VPN, or a corporate LAN reached through it.
    FortiClient,
    /// Physical LAN interfaces. Disabled by default.
    Lan,
    /// Interfaces or addresses chosen manually by the user.
    Manual,
}

impl NetworkClass {
    /// Every class, in the default Viewer priority order.
    pub const ALL: [Self; 5] = [
        Self::Tailscale,
        Self::Radmin,
        Self::FortiClient,
        Self::Lan,
        Self::Manual,
    ];

    /// Name used in the configuration file.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tailscale => "tailscale",
            Self::Radmin => "radmin",
            Self::FortiClient => "forticlient",
            Self::Lan => "lan",
            Self::Manual => "manual",
        }
    }
}

impl fmt::Display for NetworkClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the Agent allows on one network class.
///
/// All three keys are required when a class table is present: for a security
/// policy, explicit beats implicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    /// Open QUIC listeners on interfaces of this class.
    pub listen: bool,
    /// Accept attended sessions arriving through this class.
    pub attended: bool,
    /// Accept unattended sessions arriving through this class.
    pub unattended: bool,
}

impl NetworkPolicy {
    /// Listening, attended sessions only. Default for detected VPNs.
    pub const ATTENDED_ONLY: Self = Self {
        listen: true,
        attended: true,
        unattended: false,
    };

    /// Not listening at all. Default for LAN and manual entries.
    pub const DISABLED: Self = Self {
        listen: false,
        attended: false,
        unattended: false,
    };
}

/// Policy per network class. Defaults follow blueprint v2 §5.3: unattended
/// access is off everywhere until the user enables it explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkPolicies {
    /// Tailscale policy.
    pub tailscale: NetworkPolicy,
    /// Radmin VPN policy.
    pub radmin: NetworkPolicy,
    /// FortiClient / corporate LAN policy.
    pub forticlient: NetworkPolicy,
    /// Physical LAN policy.
    pub lan: NetworkPolicy,
    /// Manual entries policy.
    pub manual: NetworkPolicy,
}

impl NetworkPolicies {
    /// Policy for `class`.
    #[must_use]
    pub const fn get(&self, class: NetworkClass) -> NetworkPolicy {
        match class {
            NetworkClass::Tailscale => self.tailscale,
            NetworkClass::Radmin => self.radmin,
            NetworkClass::FortiClient => self.forticlient,
            NetworkClass::Lan => self.lan,
            NetworkClass::Manual => self.manual,
        }
    }
}

impl Default for NetworkPolicies {
    fn default() -> Self {
        Self {
            tailscale: NetworkPolicy::ATTENDED_ONLY,
            radmin: NetworkPolicy::ATTENDED_ONLY,
            forticlient: NetworkPolicy::ATTENDED_ONLY,
            lan: NetworkPolicy::DISABLED,
            manual: NetworkPolicy::DISABLED,
        }
    }
}

/// Attended-session parameters (blueprint v2 §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AttendedConfig {
    /// Seconds before an unanswered consent prompt is denied.
    pub consent_timeout_secs: u16,
    /// Seconds a session code stays valid.
    pub code_ttl_secs: u16,
    /// Failed attempts before a session code is rotated.
    pub max_code_attempts: u8,
}

impl AttendedConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        check_range(
            "agent.attended.consent_timeout_secs",
            self.consent_timeout_secs,
            5..=300,
        )?;
        check_range(
            "agent.attended.code_ttl_secs",
            self.code_ttl_secs,
            30..=3_600,
        )?;
        // Each extra attempt raises an online attacker's odds of guessing a
        // 6-digit code; keep the ceiling low.
        check_range(
            "agent.attended.max_code_attempts",
            self.max_code_attempts,
            1..=5,
        )
    }
}

impl Default for AttendedConfig {
    fn default() -> Self {
        Self {
            consent_timeout_secs: 30,
            code_ttl_secs: 300,
            max_code_attempts: 3,
        }
    }
}

/// Viewer role: this machine accesses others (blueprint v2 §5.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ViewerConfig {
    /// Order in which network classes are tried. Classes not listed are
    /// never used.
    pub network_priority: Vec<NetworkClass>,
    /// Delay between successive connection attempts in the path race.
    pub race_stagger_ms: u16,
}

impl ViewerConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        const FIELD: &str = "viewer.network_priority";
        if self.network_priority.is_empty() {
            return Err(invalid(FIELD, "must list at least one network class"));
        }
        let mut seen = BTreeSet::new();
        for class in &self.network_priority {
            if !seen.insert(*class) {
                return Err(invalid(
                    FIELD,
                    format!("`{class}` is listed more than once"),
                ));
            }
        }
        check_range(
            "viewer.race_stagger_ms",
            self.race_stagger_ms,
            0..=MAX_RACE_STAGGER_MS,
        )
    }
}

impl Default for ViewerConfig {
    fn default() -> Self {
        Self {
            network_priority: NetworkClass::ALL.to_vec(),
            race_stagger_ms: 150,
        }
    }
}

fn validate_device_name(name: &str) -> Result<(), ConfigError> {
    const FIELD: &str = "device_name";
    if name.trim().is_empty() {
        return Err(invalid(FIELD, "must not be blank"));
    }
    if name.trim() != name {
        return Err(invalid(FIELD, "must not start or end with whitespace"));
    }
    if name.len() > MAX_DEVICE_NAME_LEN {
        return Err(invalid(
            FIELD,
            format!("must be at most {MAX_DEVICE_NAME_LEN} bytes"),
        ));
    }
    if name.chars().any(char::is_control) {
        return Err(invalid(FIELD, "must not contain control characters"));
    }
    Ok(())
}

fn check_range<T>(
    field: &'static str,
    value: T,
    range: RangeInclusive<T>,
) -> Result<(), ConfigError>
where
    T: PartialOrd + fmt::Display,
{
    if range.contains(&value) {
        Ok(())
    } else {
        Err(invalid(
            field,
            format!(
                "must be between {} and {} (got {value})",
                range.start(),
                range.end()
            ),
        ))
    }
}

fn invalid(field: &'static str, reason: impl Into<String>) -> ConfigError {
    ConfigError::Invalid {
        field,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_invalid(text: &str, expected_field: &str) {
        match Config::from_toml_str(text) {
            Err(ConfigError::Invalid { field, .. }) => assert_eq!(field, expected_field),
            other => panic!("expected Invalid({expected_field}), got {other:?}"),
        }
    }

    fn assert_parse_error(text: &str) {
        match Config::from_toml_str(text) {
            Err(ConfigError::Parse(_)) => {}
            other => panic!("expected a parse error, got {other:?}"),
        }
    }

    #[test]
    fn defaults_are_valid_and_round_trip() {
        let config = Config::default();
        let text = config.to_toml_string().unwrap();
        assert_eq!(Config::from_toml_str(&text).unwrap(), config);
    }

    #[test]
    fn defaults_match_blueprint() {
        let config = Config::default();
        assert_eq!(config.agent.listen_port, 7878);
        for class in [
            NetworkClass::Tailscale,
            NetworkClass::Radmin,
            NetworkClass::FortiClient,
        ] {
            assert_eq!(
                config.agent.networks.get(class),
                NetworkPolicy::ATTENDED_ONLY
            );
        }
        for class in [NetworkClass::Lan, NetworkClass::Manual] {
            assert_eq!(config.agent.networks.get(class), NetworkPolicy::DISABLED);
        }
        assert!(
            NetworkClass::ALL
                .iter()
                .all(|&class| !config.agent.networks.get(class).unattended),
            "unattended access must be off by default on every network"
        );
        assert_eq!(config.viewer.network_priority, NetworkClass::ALL);
    }

    #[test]
    fn empty_file_means_defaults() {
        assert_eq!(Config::from_toml_str("").unwrap(), Config::default());
    }

    #[test]
    fn partial_file_keeps_other_defaults() {
        let config = Config::from_toml_str("[agent]\nlisten_port = 9000\n").unwrap();
        assert_eq!(config.agent.listen_port, 9000);
        assert_eq!(config.agent.networks, NetworkPolicies::default());
        assert_eq!(config.viewer, ViewerConfig::default());
    }

    #[test]
    fn unknown_keys_are_rejected() {
        assert_parse_error("[agent]\nlisten_prot = 9000\n");
        assert_parse_error(
            "[agent.networks.zerotier]\nlisten = true\nattended = true\nunattended = false\n",
        );
    }

    #[test]
    fn unknown_network_class_is_rejected() {
        assert_parse_error("[viewer]\nnetwork_priority = [\"zerotier\"]\n");
    }

    #[test]
    fn class_names_match_serde_names() {
        for class in NetworkClass::ALL {
            let text = format!("[viewer]\nnetwork_priority = [\"{class}\"]\n");
            let config = Config::from_toml_str(&text).unwrap();
            assert_eq!(config.viewer.network_priority, [class]);
        }
    }

    #[test]
    fn policy_tables_must_be_complete() {
        assert_parse_error("[agent.networks.lan]\nlisten = true\n");
    }

    #[test]
    fn sessions_require_listen() {
        assert_invalid(
            "[agent.networks.lan]\nlisten = false\nattended = true\nunattended = false\n",
            "agent.networks",
        );
        assert_invalid(
            "[agent.networks.tailscale]\nlisten = false\nattended = false\nunattended = true\n",
            "agent.networks",
        );
    }

    #[test]
    fn port_zero_is_rejected() {
        assert_invalid("[agent]\nlisten_port = 0\n", "agent.listen_port");
    }

    #[test]
    fn attended_ranges_are_enforced() {
        assert_invalid(
            "[agent.attended]\nmax_code_attempts = 0\n",
            "agent.attended.max_code_attempts",
        );
        assert_invalid(
            "[agent.attended]\nmax_code_attempts = 6\n",
            "agent.attended.max_code_attempts",
        );
        assert_invalid(
            "[agent.attended]\nconsent_timeout_secs = 1\n",
            "agent.attended.consent_timeout_secs",
        );
        assert_invalid(
            "[agent.attended]\ncode_ttl_secs = 7200\n",
            "agent.attended.code_ttl_secs",
        );
    }

    #[test]
    fn viewer_priority_rules() {
        assert_invalid(
            "[viewer]\nnetwork_priority = []\n",
            "viewer.network_priority",
        );
        assert_invalid(
            "[viewer]\nnetwork_priority = [\"tailscale\", \"radmin\", \"tailscale\"]\n",
            "viewer.network_priority",
        );
        assert_invalid(
            "[viewer]\nrace_stagger_ms = 2001\n",
            "viewer.race_stagger_ms",
        );
    }

    #[test]
    fn device_name_rules() {
        let with_name = |name: &str| Config {
            device_name: Some(name.to_owned()),
            ..Config::default()
        };
        assert!(with_name("office-pc").validate().is_ok());
        assert!(
            with_name(&"a".repeat(MAX_DEVICE_NAME_LEN))
                .validate()
                .is_ok()
        );

        for bad in [
            String::new(),
            "   ".to_owned(),
            " office-pc".to_owned(),
            "office\u{7}pc".to_owned(),
            "a".repeat(MAX_DEVICE_NAME_LEN + 1),
        ] {
            match with_name(&bad).validate() {
                Err(ConfigError::Invalid { field, .. }) => assert_eq!(field, "device_name"),
                other => panic!("{bad:?} should be rejected, got {other:?}"),
            }
        }
    }
}
