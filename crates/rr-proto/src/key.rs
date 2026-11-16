//! Device public keys as they appear in configuration files and messages.

use std::fmt;
use std::str::FromStr;

use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serialize, Serializer};

/// Ed25519 public key identifying a device (blueprint v2 §7.2).
///
/// Shown and stored as 64 lowercase hex characters; encoded as 32 raw bytes
/// in binary formats.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DevicePublicKey(pub [u8; 32]);

/// Error parsing a [`DevicePublicKey`] from text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("a device key is exactly 64 hexadecimal characters")]
pub struct KeyParseError;

impl DevicePublicKey {
    /// Raw key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for DevicePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for DevicePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DevicePublicKey({self})")
    }
}

impl FromStr for DevicePublicKey {
    type Err = KeyParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let text = text.as_bytes();
        if text.len() != 64 {
            return Err(KeyParseError);
        }
        let mut key = [0u8; 32];
        let (pairs, _) = text.as_chunks::<2>();
        for (out, [hi, lo]) in key.iter_mut().zip(pairs) {
            *out = (hex_value(*hi)? << 4) | hex_value(*lo)?;
        }
        Ok(Self(key))
    }
}

fn hex_value(c: u8) -> Result<u8, KeyParseError> {
    match c {
        b'0'..=b'9' => Ok(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Ok(c.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Ok(c.wrapping_sub(b'A').wrapping_add(10)),
        _ => Err(KeyParseError),
    }
}

impl Serialize for DevicePublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.collect_str(self)
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for DevicePublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct KeyVisitor;

        impl Visitor<'_> for KeyVisitor {
            type Value = DevicePublicKey;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an Ed25519 public key (64 hex characters or 32 bytes)")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                v.parse().map_err(E::custom)
            }

            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                <[u8; 32]>::try_from(v)
                    .map(DevicePublicKey)
                    .map_err(|_| E::invalid_length(v.len(), &self))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(KeyVisitor)
        } else {
            deserializer.deserialize_bytes(KeyVisitor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: DevicePublicKey = DevicePublicKey([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d,
        0x1e, 0xff,
    ]);

    #[test]
    fn hex_round_trip() {
        let text = KEY.to_string();
        assert_eq!(text.len(), 64);
        assert_eq!(text.parse::<DevicePublicKey>().unwrap(), KEY);
        assert_eq!(text.to_uppercase().parse::<DevicePublicKey>().unwrap(), KEY);
    }

    #[test]
    fn invalid_text_is_rejected() {
        assert!("".parse::<DevicePublicKey>().is_err());
        assert!("zz".repeat(32).parse::<DevicePublicKey>().is_err());
        assert!("00".repeat(31).parse::<DevicePublicKey>().is_err());
        assert!("é".repeat(32).parse::<DevicePublicKey>().is_err());
    }

    #[test]
    fn binary_round_trip() {
        let bytes = postcard::to_allocvec(&KEY).unwrap();
        assert_eq!(
            postcard::from_bytes::<DevicePublicKey>(&bytes).unwrap(),
            KEY
        );
        let short = postcard::to_allocvec(&[1u8; 31].as_slice()).unwrap();
        assert!(postcard::from_bytes::<DevicePublicKey>(&short).is_err());
    }
}
