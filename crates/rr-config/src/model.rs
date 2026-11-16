//! Configuration data model and validation rules.

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;
use std::ops::RangeInclusive;

use ipnet::IpNet;
pub use rr_proto::NetworkClass;
use serde::{Deserialize, Serialize};

use crate::ConfigError;

/// Maximum length of a device name, in bytes. Matches the protocol limit for
/// names sent to peers.
pub const MAX_DEVICE_NAME_LEN: usize = rr_proto::MAX_DEVICE_NAME;

/// Maximum number of entries in one `allowed_sources` list.
pub const MAX_ALLOWED_SOURCES: usize = 64;

/// Maximum number of entries in [`AgentConfig::manual_listen`].
pub const MAX_MANUAL_LISTEN: usize = 16;

/// Name used when neither the configuration nor the OS provides one.
const FALLBACK_DEVICE_NAME: &str = "unnamed";

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
            validate_name("device_name", name)?;
        }
        self.agent.validate()?;
        self.viewer.validate()
    }

    /// Name to present to peers: the configured one, else the OS hostname
    /// passed in by the caller, else a fixed fallback. Always valid.
    #[must_use]
    pub fn effective_device_name(&self, hostname: Option<&str>) -> String {
        match (&self.device_name, hostname) {
            (Some(name), _) => name.clone(),
            (None, Some(host)) => sanitize_device_name(host),
            (None, None) => FALLBACK_DEVICE_NAME.to_owned(),
        }
    }
}

/// Agent role: this machine is being accessed (blueprint v2 §5.3, §7.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentConfig {
    /// UDP port of the QUIC listeners.
    pub listen_port: u16,
    /// Local addresses to listen on for the `manual` network class.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub manual_listen: Vec<IpAddr>,
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
            self.networks.get(class).validate(class)?;
        }
        self.validate_manual_listen()?;
        self.attended.validate()
    }

    fn validate_manual_listen(&self) -> Result<(), ConfigError> {
        const FIELD: &str = "agent.manual_listen";
        if self.networks.manual.listen && self.manual_listen.is_empty() {
            return Err(invalid(
                FIELD,
                "`networks.manual.listen = true` needs at least one address here",
            ));
        }
        if self.manual_listen.len() > MAX_MANUAL_LISTEN {
            return Err(invalid(
                FIELD,
                format!("at most {MAX_MANUAL_LISTEN} addresses are allowed"),
            ));
        }
        let mut seen = BTreeSet::new();
        for addr in &self.manual_listen {
            // Wildcard binds would expose the Agent on every interface,
            // defeating per-network policy (blueprint v2 §5.3).
            if addr.is_unspecified() || addr.is_multicast() {
                return Err(invalid(
                    FIELD,
                    format!("`{addr}` is not a unicast interface address"),
                ));
            }
            if !seen.insert(*addr) {
                return Err(invalid(FIELD, format!("`{addr}` is listed more than once")));
            }
        }
        Ok(())
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            listen_port: Self::DEFAULT_PORT,
            manual_listen: Vec::new(),
            networks: NetworkPolicies::default(),
            attended: AttendedConfig::default(),
        }
    }
}

/// What the Agent allows on one network class.
///
/// `listen`, `attended` and `unattended` are required when a class table is
/// present: for a security policy, explicit beats implicit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    /// Open QUIC listeners on interfaces of this class.
    pub listen: bool,
    /// Accept attended sessions arriving through this class.
    pub attended: bool,
    /// Accept unattended sessions arriving through this class.
    pub unattended: bool,
    /// Source networks allowed to connect. Packets from anywhere else are
    /// dropped before any TLS work. Empty means automatic: the VPN's own
    /// range for Tailscale, otherwise the subnets of the listening interface.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_sources: Vec<IpNet>,
}

impl NetworkPolicy {
    /// Listening, attended sessions only. Default for detected VPNs.
    pub const ATTENDED_ONLY: Self = Self {
        listen: true,
        attended: true,
        unattended: false,
        allowed_sources: Vec::new(),
    };

    /// Not listening at all. Default for LAN and manual entries.
    pub const DISABLED: Self = Self {
        listen: false,
        attended: false,
        unattended: false,
        allowed_sources: Vec::new(),
    };

    fn validate(&self, class: NetworkClass) -> Result<(), ConfigError> {
        const FIELD: &str = "agent.networks";
        if (self.attended || self.unattended) && !self.listen {
            return Err(invalid(
                FIELD,
                format!("`{class}` accepts sessions but has `listen = false`"),
            ));
        }
        if self.allowed_sources.len() > MAX_ALLOWED_SOURCES {
            return Err(invalid(
                FIELD,
                format!("`{class}.allowed_sources` has more than {MAX_ALLOWED_SOURCES} entries"),
            ));
        }
        for net in &self.allowed_sources {
            // `10.0.0.5/8` is almost always a typo for a host or for
            // `10.0.0.0/8`; refusing it avoids silently widening access.
            if net.trunc() != *net {
                return Err(invalid(
                    FIELD,
                    format!(
                        "`{class}.allowed_sources`: `{net}` has host bits set (did you mean `{}`?)",
                        net.trunc()
                    ),
                ));
            }
        }
        Ok(())
    }
}

/// Policy per network class. Defaults follow blueprint v2 §5.3: unattended
/// access is off everywhere until the user enables it explicitly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    pub const fn get(&self, class: NetworkClass) -> &NetworkPolicy {
        match class {
            NetworkClass::Tailscale => &self.tailscale,
            NetworkClass::Radmin => &self.radmin,
            NetworkClass::FortiClient => &self.forticlient,
            NetworkClass::Lan => &self.lan,
            NetworkClass::Manual => &self.manual,
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
    /// Accept pairing requests from unknown devices. When `false`, unknown
    /// keys are rejected during the TLS handshake.
    pub pairing_enabled: bool,
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
            pairing_enabled: true,
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

/// Characters never allowed in a device name: control characters, and
/// bidirectional-text overrides that could make a consent prompt display
/// something other than what was sent.
fn is_forbidden_name_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        )
}

/// Turns an untrusted name (a peer's `Hello`, an OS hostname) into one that
/// passes validation: forbidden characters removed, whitespace trimmed,
/// truncated to [`MAX_DEVICE_NAME_LEN`] bytes on a character boundary.
#[must_use]
pub fn sanitize_device_name(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(MAX_DEVICE_NAME_LEN));
    for c in raw.trim().chars().filter(|&c| !is_forbidden_name_char(c)) {
        if out.len().saturating_add(c.len_utf8()) > MAX_DEVICE_NAME_LEN {
            break;
        }
        out.push(c);
    }
    let trimmed = out.trim();
    if trimmed.is_empty() {
        FALLBACK_DEVICE_NAME.to_owned()
    } else {
        trimmed.to_owned()
    }
}

/// Validates a device name stored in a file under `field`.
pub(crate) fn validate_name(field: &'static str, name: &str) -> Result<(), ConfigError> {
    if name.trim().is_empty() {
        return Err(invalid(field, "must not be blank"));
    }
    if name.trim() != name {
        return Err(invalid(field, "must not start or end with whitespace"));
    }
    if name.len() > MAX_DEVICE_NAME_LEN {
        return Err(invalid(
            field,
            format!("must be at most {MAX_DEVICE_NAME_LEN} bytes"),
        ));
    }
    if name.chars().any(is_forbidden_name_char) {
        return Err(invalid(
            field,
            "must not contain control or text-direction characters",
        ));
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

pub(crate) fn invalid(field: &'static str, reason: impl Into<String>) -> ConfigError {
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
        assert!(config.agent.attended.pairing_enabled);
        for class in [
            NetworkClass::Tailscale,
            NetworkClass::Radmin,
            NetworkClass::FortiClient,
        ] {
            assert_eq!(
                config.agent.networks.get(class),
                &NetworkPolicy::ATTENDED_ONLY
            );
        }
        for class in [NetworkClass::Lan, NetworkClass::Manual] {
            assert_eq!(config.agent.networks.get(class), &NetworkPolicy::DISABLED);
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
    fn allowed_sources_parse_and_round_trip() {
        let text = "[agent.networks.lan]\nlisten = true\nattended = true\nunattended = false\n\
                    allowed_sources = [\"192.168.10.0/24\", \"fd00::/8\"]\n";
        let config = Config::from_toml_str(text).unwrap();
        assert_eq!(config.agent.networks.lan.allowed_sources.len(), 2);
        let again = Config::from_toml_str(&config.to_toml_string().unwrap()).unwrap();
        assert_eq!(again, config);
    }

    #[test]
    fn allowed_sources_rules() {
        // Not a network at all.
        assert_parse_error(
            "[agent.networks.lan]\nlisten = true\nattended = true\nunattended = false\n\
             allowed_sources = [\"192.168.10.5\"]\n",
        );
        // Host bits set.
        assert_invalid(
            "[agent.networks.lan]\nlisten = true\nattended = true\nunattended = false\n\
             allowed_sources = [\"10.1.2.3/8\"]\n",
            "agent.networks",
        );
        // Too many entries.
        let many: Vec<String> = (0..=MAX_ALLOWED_SOURCES)
            .map(|i| format!("\"10.{i}.0.0/16\""))
            .collect();
        assert_invalid(
            &format!(
                "[agent.networks.lan]\nlisten = true\nattended = true\nunattended = false\n\
                 allowed_sources = [{}]\n",
                many.join(", ")
            ),
            "agent.networks",
        );
    }

    #[test]
    fn manual_listen_rules() {
        let manual_on =
            "[agent.networks.manual]\nlisten = true\nattended = true\nunattended = false\n";
        assert_invalid(manual_on, "agent.manual_listen");

        let ok = format!("[agent]\nmanual_listen = [\"10.8.0.2\"]\n{manual_on}");
        let config = Config::from_toml_str(&ok).unwrap();
        assert_eq!(config.agent.manual_listen.len(), 1);

        for bad in ["0.0.0.0", "::", "224.0.0.1"] {
            assert_invalid(
                &format!("[agent]\nmanual_listen = [\"{bad}\"]\n"),
                "agent.manual_listen",
            );
        }
        assert_invalid(
            "[agent]\nmanual_listen = [\"10.8.0.2\", \"10.8.0.2\"]\n",
            "agent.manual_listen",
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
        assert!(with_name("escritório").validate().is_ok());
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
            "office\u{202E}cp".to_owned(),
            "a".repeat(MAX_DEVICE_NAME_LEN + 1),
        ] {
            match with_name(&bad).validate() {
                Err(ConfigError::Invalid { field, .. }) => assert_eq!(field, "device_name"),
                other => panic!("{bad:?} should be rejected, got {other:?}"),
            }
        }
    }

    #[test]
    fn sanitized_names_always_validate() {
        for raw in [
            "",
            "   ",
            "  office-pc  ",
            "evil\u{202E}fdp.exe",
            "tab\there",
            &"é".repeat(MAX_DEVICE_NAME_LEN),
            &format!("{} x", "a".repeat(MAX_DEVICE_NAME_LEN - 1)),
        ] {
            let name = sanitize_device_name(raw);
            assert!(
                validate_name("device_name", &name).is_ok(),
                "{raw:?} -> {name:?}"
            );
        }
        assert_eq!(sanitize_device_name("  office-pc "), "office-pc");
        assert_eq!(sanitize_device_name("\u{1}\u{2}"), FALLBACK_DEVICE_NAME);
    }

    #[test]
    fn effective_name_precedence() {
        let named = Config {
            device_name: Some("desk".to_owned()),
            ..Config::default()
        };
        assert_eq!(named.effective_device_name(Some("HOST")), "desk");
        assert_eq!(
            Config::default().effective_device_name(Some(" HOST ")),
            "HOST"
        );
        assert_eq!(
            Config::default().effective_device_name(None),
            FALLBACK_DEVICE_NAME
        );
    }
}
