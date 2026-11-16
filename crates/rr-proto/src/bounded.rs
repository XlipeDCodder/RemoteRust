//! Length-limited wrappers. Their `Deserialize` implementations reject
//! oversized input *before* allocating, so a hostile peer cannot make us
//! reserve memory by announcing huge lengths.

use std::fmt;
use std::marker::PhantomData;
use std::ops::Deref;

use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::{Deserialize, Serialize, Serializer};

/// A value was longer than its bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("length {len} exceeds the limit of {max}")]
pub struct TooLong {
    /// Actual length.
    pub len: usize,
    /// Maximum allowed length.
    pub max: usize,
}

fn check(len: usize, max: usize) -> Result<(), TooLong> {
    if len > max {
        Err(TooLong { len, max })
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// BoundedString
// ---------------------------------------------------------------------------

/// UTF-8 string of at most `N` bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct BoundedString<const N: usize>(String);

impl<const N: usize> BoundedString<N> {
    /// Wraps `value` if it fits in `N` bytes.
    ///
    /// # Errors
    /// [`TooLong`] if `value` is longer than `N` bytes.
    pub fn new(value: impl Into<String>) -> Result<Self, TooLong> {
        let value = value.into();
        check(value.len(), N)?;
        Ok(Self(value))
    }

    /// Keeps the longest prefix of `value` that fits in `N` bytes without
    /// splitting a character.
    #[must_use]
    pub fn truncating(value: &str) -> Self {
        let mut end = value.len().min(N);
        while !value.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        Self(value.get(..end).unwrap_or_default().to_owned())
    }

    /// Borrowed view of the string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Unwraps the inner `String`.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl<const N: usize> Deref for BoundedString<N> {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl<const N: usize> fmt::Display for BoundedString<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<const N: usize> Serialize for BoundedString<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de, const N: usize> Deserialize<'de> for BoundedString<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrVisitor<const N: usize>;

        impl<const N: usize> Visitor<'_> for StrVisitor<N> {
            type Value = BoundedString<N>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a string of at most {N} bytes")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                if v.len() > N {
                    return Err(E::invalid_length(v.len(), &self));
                }
                Ok(BoundedString(v.to_owned()))
            }

            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                if v.len() > N {
                    return Err(E::invalid_length(v.len(), &self));
                }
                Ok(BoundedString(v))
            }
        }

        deserializer.deserialize_str(StrVisitor::<N>)
    }
}

// ---------------------------------------------------------------------------
// BoundedBytes
// ---------------------------------------------------------------------------

/// Byte buffer of at most `N` bytes.
#[derive(Clone, PartialEq, Eq, Hash, Default)]
pub struct BoundedBytes<const N: usize>(Vec<u8>);

impl<const N: usize> BoundedBytes<N> {
    /// Wraps `value` if it fits in `N` bytes.
    ///
    /// # Errors
    /// [`TooLong`] if `value` is longer than `N` bytes.
    pub fn new(value: impl Into<Vec<u8>>) -> Result<Self, TooLong> {
        let value = value.into();
        check(value.len(), N)?;
        Ok(Self(value))
    }

    /// Borrowed view of the bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Unwraps the inner `Vec`.
    #[must_use]
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl<const N: usize> fmt::Debug for BoundedBytes<N> {
    // Never print contents: these buffers may carry key-exchange material.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BoundedBytes<{N}>({} bytes)", self.0.len())
    }
}

impl<const N: usize> Deref for BoundedBytes<N> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> Serialize for BoundedBytes<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de, const N: usize> Deserialize<'de> for BoundedBytes<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BytesVisitor<const N: usize>;

        impl<'de, const N: usize> Visitor<'de> for BytesVisitor<N> {
            type Value = BoundedBytes<N>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "at most {N} bytes")
            }

            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                if v.len() > N {
                    return Err(E::invalid_length(v.len(), &self));
                }
                Ok(BoundedBytes(v.to_vec()))
            }

            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                if v.len() > N {
                    return Err(E::invalid_length(v.len(), &self));
                }
                Ok(BoundedBytes(v))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Self::Value, A::Error> {
                bounded_seq::<u8, N, A>(seq).map(BoundedBytes)
            }
        }

        deserializer.deserialize_bytes(BytesVisitor::<N>)
    }
}

// ---------------------------------------------------------------------------
// BoundedVec
// ---------------------------------------------------------------------------

/// Vector of at most `N` elements.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BoundedVec<T, const N: usize>(Vec<T>);

impl<T, const N: usize> BoundedVec<T, N> {
    /// Wraps `items` if there are at most `N` of them.
    ///
    /// # Errors
    /// [`TooLong`] if `items` has more than `N` elements.
    pub fn new(items: Vec<T>) -> Result<Self, TooLong> {
        check(items.len(), N)?;
        Ok(Self(items))
    }

    /// Keeps at most the first `N` elements.
    #[must_use]
    pub fn truncating(mut items: Vec<T>) -> Self {
        items.truncate(N);
        Self(items)
    }

    /// Unwraps the inner `Vec`.
    #[must_use]
    pub fn into_inner(self) -> Vec<T> {
        self.0
    }
}

impl<T, const N: usize> Default for BoundedVec<T, N> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T, const N: usize> Deref for BoundedVec<T, N> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        &self.0
    }
}

impl<T: Serialize, const N: usize> Serialize for BoundedVec<T, N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for BoundedVec<T, N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SeqVisitor<T, const N: usize>(PhantomData<T>);

        impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for SeqVisitor<T, N> {
            type Value = BoundedVec<T, N>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a sequence of at most {N} elements")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Self::Value, A::Error> {
                bounded_seq::<T, N, A>(seq).map(BoundedVec)
            }
        }

        deserializer.deserialize_seq(SeqVisitor::<T, N>(PhantomData))
    }
}

/// Collects at most `N` elements, checking the announced length first and
/// never pre-allocating more than `N` slots.
fn bounded_seq<'de, T, const N: usize, A>(mut seq: A) -> Result<Vec<T>, A::Error>
where
    T: Deserialize<'de>,
    A: SeqAccess<'de>,
{
    let hint = seq.size_hint().unwrap_or(0);
    if hint > N {
        return Err(de::Error::invalid_length(hint, &"a bounded sequence"));
    }
    let mut items = Vec::with_capacity(hint);
    while let Some(item) = seq.next_element()? {
        if items.len() >= N {
            return Err(de::Error::invalid_length(
                items.len().saturating_add(1),
                &"a bounded sequence",
            ));
        }
        items.push(item);
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_bound_is_enforced() {
        assert!(BoundedString::<4>::new("abcd").is_ok());
        assert_eq!(
            BoundedString::<4>::new("abcde"),
            Err(TooLong { len: 5, max: 4 })
        );
    }

    #[test]
    fn truncation_respects_char_boundaries() {
        // "é" is 2 bytes: a 3-byte limit must not split the second one.
        assert_eq!(BoundedString::<3>::truncating("éé").as_str(), "é");
        assert_eq!(BoundedString::<64>::truncating("pc").as_str(), "pc");
    }

    #[test]
    fn oversized_values_are_rejected_on_decode() {
        let long = postcard::to_allocvec("abcdef").unwrap();
        assert!(postcard::from_bytes::<BoundedString<5>>(&long).is_err());
        assert!(postcard::from_bytes::<BoundedString<6>>(&long).is_ok());

        let bytes = postcard::to_allocvec(&BoundedBytes::<8>::new(vec![1; 8]).unwrap()).unwrap();
        assert!(postcard::from_bytes::<BoundedBytes<7>>(&bytes).is_err());
        assert!(postcard::from_bytes::<BoundedBytes<8>>(&bytes).is_ok());

        let items = postcard::to_allocvec(&vec![1u8, 2, 3]).unwrap();
        assert!(postcard::from_bytes::<BoundedVec<u8, 2>>(&items).is_err());
        assert!(postcard::from_bytes::<BoundedVec<u8, 3>>(&items).is_ok());
    }

    #[test]
    fn huge_announced_length_does_not_allocate() {
        // varint(u32::MAX) followed by nothing: must fail fast, not reserve 4 GiB.
        let evil = [0xFF, 0xFF, 0xFF, 0xFF, 0x0F];
        assert!(postcard::from_bytes::<BoundedVec<u64, 16>>(&evil).is_err());
        assert!(postcard::from_bytes::<BoundedBytes<16>>(&evil).is_err());
        assert!(postcard::from_bytes::<BoundedString<16>>(&evil).is_err());
    }

    #[test]
    fn bytes_debug_hides_contents() {
        let secret = BoundedBytes::<4>::new(vec![0xAA, 0xBB]).unwrap();
        assert_eq!(format!("{secret:?}"), "BoundedBytes<4>(2 bytes)");
    }
}
