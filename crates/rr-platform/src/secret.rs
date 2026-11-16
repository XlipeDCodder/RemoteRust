//! At-rest protection for small secrets such as the device private key
//! (blueprint v2 §7.2).
//!
//! - Windows: DPAPI, bound to the current user account. A copied file is
//!   useless on another account or machine.
//! - Linux: no transformation. Callers store the file with mode `0600`
//!   (owner read/write only).

use std::io;

use zeroize::Zeroizing;

/// How a stored secret is protected. Persisted next to the data so a file
/// written by one scheme is never misread by another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Scheme {
    /// Windows DPAPI, current-user scope.
    Dpapi = 1,
    /// Plain bytes, protected by file permissions only.
    FilePermissions = 2,
}

impl Scheme {
    /// The scheme used on this platform.
    pub const NATIVE: Self = if cfg!(windows) {
        Self::Dpapi
    } else {
        Self::FilePermissions
    };

    /// Byte persisted next to protected data.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Parses a persisted scheme byte.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Dpapi),
            2 => Some(Self::FilePermissions),
            _ => None,
        }
    }
}

/// Protects `plain` with [`Scheme::NATIVE`].
///
/// # Errors
/// The OS error if protection fails.
pub fn protect(plain: &[u8]) -> io::Result<Vec<u8>> {
    #[cfg(windows)]
    {
        crate::win::dpapi::protect(plain)
    }
    #[cfg(not(windows))]
    {
        Ok(plain.to_vec())
    }
}

/// Reverses [`protect`]. The result is wiped from memory when dropped.
///
/// # Errors
/// The OS error if the data cannot be unprotected (for example a DPAPI blob
/// created by another user account).
pub fn unprotect(blob: &[u8]) -> io::Result<Zeroizing<Vec<u8>>> {
    #[cfg(windows)]
    {
        crate::win::dpapi::unprotect(blob)
    }
    #[cfg(not(windows))]
    {
        Ok(Zeroizing::new(blob.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let secret = b"not really a key";
        let blob = protect(secret).unwrap();
        if Scheme::NATIVE == Scheme::Dpapi {
            assert_ne!(
                blob.as_slice(),
                secret.as_slice(),
                "DPAPI must not store plaintext"
            );
        }
        assert_eq!(unprotect(&blob).unwrap().as_slice(), secret.as_slice());
    }

    #[test]
    fn empty_secret_round_trips() {
        let blob = protect(&[]).unwrap();
        assert!(unprotect(&blob).unwrap().is_empty());
    }

    #[test]
    fn scheme_byte_round_trip() {
        for scheme in [Scheme::Dpapi, Scheme::FilePermissions] {
            assert_eq!(Scheme::from_byte(scheme.as_byte()), Some(scheme));
        }
        assert_eq!(Scheme::from_byte(0), None);
    }

    #[cfg(windows)]
    #[test]
    fn tampered_blob_is_rejected() {
        let mut blob = protect(b"secret").unwrap();
        if let Some(last) = blob.last_mut() {
            *last ^= 0xFF;
        }
        assert!(unprotect(&blob).is_err());
    }
}
