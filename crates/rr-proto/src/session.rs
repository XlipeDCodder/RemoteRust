//! Session grants: permissions and monitor descriptions (blueprint v2 §6.4,
//! §7.3).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::BoundedString;

/// Maximum number of monitors an Agent describes.
pub const MAX_MONITORS: usize = 16;

/// Maximum length of a monitor name, in bytes.
pub const MAX_MONITOR_NAME: usize = 32;

/// What a Viewer may do in a session: a set of flags.
///
/// Decoding rejects unknown bits, so a newer peer can never smuggle in a
/// permission this build does not understand.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct Permissions(u8);

impl Permissions {
    /// No permission at all.
    pub const NONE: Self = Self(0);
    /// See the screen.
    pub const VIEW: Self = Self(1);
    /// Send keyboard and mouse input (M3).
    pub const CONTROL: Self = Self(1 << 1);
    /// Exchange clipboard text (M7).
    pub const CLIPBOARD: Self = Self(1 << 2);
    /// Transfer files (M7).
    pub const FILES: Self = Self(1 << 3);

    const KNOWN: u8 = 0b1111;
    const NAMES: [(Self, &'static str); 4] = [
        (Self::VIEW, "view"),
        (Self::CONTROL, "control"),
        (Self::CLIPBOARD, "clipboard"),
        (Self::FILES, "files"),
    ];

    /// Whether every flag of `other` is set in `self`.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Flags set in both.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Flags set in either.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether no flag is set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The raw bits.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Human-readable names of the set flags, for prompts and logs.
    pub fn names(self) -> impl Iterator<Item = &'static str> {
        Self::NAMES
            .into_iter()
            .filter(move |(flag, _)| self.contains(*flag))
            .map(|(_, name)| name)
    }
}

/// A byte with bits outside the known permission flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("unknown permission bits {0:#04x}")]
pub struct UnknownPermissions(pub u8);

impl TryFrom<u8> for Permissions {
    type Error = UnknownPermissions;

    fn try_from(bits: u8) -> Result<Self, Self::Error> {
        if bits & !Self::KNOWN == 0 {
            Ok(Self(bits))
        } else {
            Err(UnknownPermissions(bits))
        }
    }
}

impl From<Permissions> for u8 {
    fn from(permissions: Permissions) -> Self {
        permissions.0
    }
}

impl fmt::Debug for Permissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Permissions({self})")
    }
}

impl fmt::Display for Permissions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return f.write_str("none");
        }
        for (i, name) in self.names().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            f.write_str(name)?;
        }
        Ok(())
    }
}

/// One monitor of the Agent, as announced in `SessionStart`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorInfo {
    /// Identifier used by `SessionStart::monitor` (and `SelectMonitor`, M7).
    pub id: u8,
    /// OS name, e.g. `DISPLAY1`.
    pub name: BoundedString<MAX_MONITOR_NAME>,
    /// Width in physical pixels.
    pub width: u16,
    /// Height in physical pixels.
    pub height: u16,
    /// Whether this is the primary monitor.
    pub primary: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissions_reject_unknown_bits() {
        assert_eq!(
            Permissions::try_from(0b0011),
            Ok(Permissions::VIEW.union(Permissions::CONTROL))
        );
        assert_eq!(
            Permissions::try_from(0b1_0000),
            Err(UnknownPermissions(0b1_0000))
        );
        assert!(Permissions::try_from(0xFF).is_err());
    }

    #[test]
    fn permissions_set_operations_and_names() {
        let both = Permissions::VIEW.union(Permissions::CLIPBOARD);
        assert!(both.contains(Permissions::VIEW));
        assert!(!both.contains(Permissions::CONTROL));
        assert_eq!(both.intersection(Permissions::VIEW), Permissions::VIEW);
        assert_eq!(both.to_string(), "view, clipboard");
        assert_eq!(Permissions::NONE.to_string(), "none");
    }
}
