//! Device identity: one Ed25519 key pair per user account and machine
//! (blueprint v2 §7.2).
//!
//! The public key *is* the device identity. Peers pin it at pairing time
//! and check it in every TLS handshake; the self-signed certificate is only
//! a container for TLS and its other fields are ignored.
//!
//! On disk (`device.key` in the data directory):
//!
//! ```text
//! "RRID" | format version (1) | protection scheme (1) | protected PKCS#8
//! ```
//!
//! The PKCS#8 document is protected with [`rr_platform::secret`] (DPAPI on
//! Windows, owner-only file mode on Linux) and is never logged.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rcgen::{CertificateParams, DistinguishedName, DnType, PKCS_ED25519};
use ring::digest;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};
use rr_config::ConfigError;
use rr_platform::secret::{self, Scheme};
use rr_proto::DevicePublicKey;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use rustls::{CertificateError, Error as TlsError};
use zeroize::{Zeroize as _, Zeroizing};

/// File name of the device identity inside the data directory.
pub const IDENTITY_FILE_NAME: &str = "device.key";

/// Name placed in the self-signed certificate. Never validated: peers are
/// authenticated by pinned key only. `.invalid` guarantees it can never
/// collide with a real DNS name (RFC 2606).
pub(crate) const CERT_SERVER_NAME: &str = "rustremote.invalid";

const MAGIC: &[u8; 4] = b"RRID";
const FORMAT_VERSION: u8 = 1;
const MAX_IDENTITY_FILE_SIZE: u64 = 4 * 1024;

/// DER prefix of an Ed25519 `SubjectPublicKeyInfo` (RFC 8410): SEQUENCE,
/// AlgorithmIdentifier { id-Ed25519 }, BIT STRING of 33 bytes (0 unused bits).
/// The 32-byte key follows.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Errors loading or creating the device identity.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// The identity file could not be read or written.
    #[error(transparent)]
    File(#[from] ConfigError),

    /// The file is not a valid identity file.
    #[error("{} is not a usable identity file: {reason}", .path.display())]
    Corrupt {
        /// Offending file.
        path: PathBuf,
        /// What is wrong with it.
        reason: &'static str,
    },

    /// The key could not be unprotected, typically because the file was
    /// created by another user account or copied from another machine.
    #[error("cannot unprotect {} (created by another account or machine?)", .path.display())]
    Unprotect {
        /// Offending file.
        path: PathBuf,
        /// OS error.
        #[source]
        source: std::io::Error,
    },

    /// The key could not be protected before being stored.
    #[error("cannot protect the device key")]
    Protect(#[source] std::io::Error),

    /// The OS random generator failed.
    #[error("device key generation failed")]
    KeyGeneration,

    /// The stored key is not a valid Ed25519 PKCS#8 v2 document.
    #[error("the device key is not a valid Ed25519 key")]
    InvalidKey,

    /// The self-signed certificate could not be built.
    #[error("certificate generation failed")]
    Certificate(#[from] rcgen::Error),

    /// rustls refused the key or certificate.
    #[error("TLS key setup failed")]
    Tls(#[from] TlsError),
}

/// This device's key pair and certificate, ready for TLS.
#[derive(Clone)]
pub struct DeviceIdentity {
    public_key: DevicePublicKey,
    certified: Arc<CertifiedKey>,
}

impl fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl DeviceIdentity {
    /// Creates a fresh identity in memory (nothing is stored).
    ///
    /// # Errors
    /// [`IdentityError::KeyGeneration`] or a certificate/TLS setup error.
    pub fn generate() -> Result<Self, IdentityError> {
        Self::from_pkcs8(&generate_pkcs8()?)
    }

    /// Builds an identity from an Ed25519 PKCS#8 v2 document.
    ///
    /// # Errors
    /// [`IdentityError::InvalidKey`] for anything but a well-formed Ed25519
    /// key, or a certificate/TLS setup error.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, IdentityError> {
        // Strict parse: checks the embedded public key matches the seed.
        let public_key = Ed25519KeyPair::from_pkcs8(pkcs8)
            .ok()
            .and_then(|pair| <[u8; 32]>::try_from(pair.public_key().as_ref()).ok())
            .map(DevicePublicKey)
            .ok_or(IdentityError::InvalidKey)?;

        let key_der = PrivatePkcs8KeyDer::from(pkcs8);
        let cert = self_signed_cert(&key_der)?;
        let signer = rustls::crypto::ring::sign::any_eddsa_type(&key_der)?;
        let certified = CertifiedKey::new(vec![cert], signer);
        certified.keys_match()?;
        Ok(Self {
            public_key,
            certified: Arc::new(certified),
        })
    }

    /// Loads the identity stored at `path`.
    ///
    /// # Errors
    /// [`IdentityError::File`] (a missing file reports
    /// [`ConfigError::is_not_found`]), [`IdentityError::Corrupt`],
    /// [`IdentityError::Unprotect`] or [`IdentityError::InvalidKey`].
    pub fn load(path: &Path) -> Result<Self, IdentityError> {
        let bytes = Zeroizing::new(rr_config::read_limited(path, MAX_IDENTITY_FILE_SIZE)?);
        let corrupt = |reason| IdentityError::Corrupt {
            path: path.to_path_buf(),
            reason,
        };
        #[cfg(unix)]
        check_owner_only(path).map_err(corrupt)?;

        let payload = parse_file(&bytes).map_err(corrupt)?;
        let pkcs8 = secret::unprotect(payload).map_err(|source| IdentityError::Unprotect {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_pkcs8(&pkcs8)
    }

    /// Loads the identity at `path`, creating and storing a new one if the
    /// file does not exist. Safe against concurrent first starts: every
    /// process ends up with the key that was stored.
    ///
    /// # Errors
    /// Same as [`Self::load`], plus storage errors when creating.
    pub fn load_or_create(path: &Path) -> Result<Self, IdentityError> {
        match Self::load(path) {
            Err(IdentityError::File(err)) if err.is_not_found() => {}
            other => return other,
        }

        let pkcs8 = generate_pkcs8()?;
        let identity = Self::from_pkcs8(&pkcs8)?;
        if rr_config::write_new(path, &encode_file(&pkcs8)?)? {
            tracing::info!(
                fingerprint = %identity.fingerprint(),
                "created a new device identity"
            );
            Ok(identity)
        } else {
            // Another process stored its key first; that one is the identity.
            Self::load(path)
        }
    }

    /// The device public key peers pin.
    #[must_use]
    pub const fn public_key(&self) -> DevicePublicKey {
        self.public_key
    }

    /// Short, human-comparable form of the public key.
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(&self.public_key)
    }

    /// Certificate and signing key for rustls.
    pub(crate) fn certified_key(&self) -> Arc<CertifiedKey> {
        Arc::clone(&self.certified)
    }
}

/// Location of the identity file in the per-user data directory.
#[must_use]
pub fn default_identity_path() -> Option<PathBuf> {
    rr_config::default_data_dir().map(|dir| dir.join(IDENTITY_FILE_NAME))
}

/// Extracts the Ed25519 device key from a peer certificate.
///
/// Only the key matters; every other certificate field is ignored. Any
/// other key type is rejected.
pub(crate) fn peer_public_key(cert: &CertificateDer<'_>) -> Result<DevicePublicKey, TlsError> {
    let bad = || TlsError::InvalidCertificate(CertificateError::BadEncoding);
    let parsed = webpki::EndEntityCert::try_from(cert).map_err(|_| bad())?;
    let spki = parsed.subject_public_key_info();
    let raw = spki
        .as_ref()
        .strip_prefix(ED25519_SPKI_PREFIX.as_slice())
        .ok_or_else(bad)?;
    <[u8; 32]>::try_from(raw)
        .map(DevicePublicKey)
        .map_err(|_| bad())
}

fn generate_pkcs8() -> Result<Zeroizing<Vec<u8>>, IdentityError> {
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| IdentityError::KeyGeneration)?;
    Ok(Zeroizing::new(document.as_ref().to_vec()))
}

fn self_signed_cert(
    key_der: &PrivatePkcs8KeyDer<'_>,
) -> Result<CertificateDer<'static>, IdentityError> {
    let mut key_pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(key_der, &PKCS_ED25519)?;
    let mut params = CertificateParams::new(vec![CERT_SERVER_NAME.to_owned()])?;
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "RustRemote device");
    params.distinguished_name = name;
    let cert = params.self_signed(&key_pair).map(|cert| cert.der().clone());
    // rcgen keeps its own copy of the PKCS#8 bytes; wipe it.
    key_pair.zeroize();
    Ok(cert?)
}

fn encode_file(pkcs8: &[u8]) -> Result<Zeroizing<Vec<u8>>, IdentityError> {
    // On Linux "protected" means unchanged, so treat it as secret either way.
    let protected = Zeroizing::new(secret::protect(pkcs8).map_err(IdentityError::Protect)?);
    let mut file = Zeroizing::new(Vec::with_capacity(protected.len().saturating_add(6)));
    file.extend_from_slice(MAGIC);
    file.push(FORMAT_VERSION);
    file.push(Scheme::NATIVE.as_byte());
    file.extend_from_slice(&protected);
    Ok(file)
}

fn parse_file(bytes: &[u8]) -> Result<&[u8], &'static str> {
    const TRUNCATED: &str = "truncated file";
    let (magic, rest) = bytes.split_first_chunk::<4>().ok_or(TRUNCATED)?;
    if magic != MAGIC {
        return Err("not a RustRemote identity file");
    }
    let (&version, rest) = rest.split_first().ok_or(TRUNCATED)?;
    if version != FORMAT_VERSION {
        return Err("unsupported format version");
    }
    let (&scheme, payload) = rest.split_first().ok_or(TRUNCATED)?;
    match Scheme::from_byte(scheme) {
        Some(scheme) if scheme == Scheme::NATIVE => Ok(payload),
        Some(_) => Err("protected with a scheme this platform cannot read"),
        None => Err("unknown protection scheme"),
    }
}

/// Refuses key files readable or writable by other users, like OpenSSH.
#[cfg(unix)]
fn check_owner_only(path: &Path) -> Result<(), &'static str> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(path)
        .map_err(|_| "cannot read file permissions")?
        .permissions()
        .mode();
    if mode & 0o077 == 0 {
        Ok(())
    } else {
        Err("file is accessible by other users (expected mode 0600)")
    }
}

/// Human-comparable digest of a device key: 120 bits of SHA-256 in
/// Crockford base32, as six groups of four (`XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`).
///
/// Shown on both screens so users can confirm out of band that they paired
/// with the expected device.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint([u8; 15]);

impl Fingerprint {
    /// Domain separation: these digests are never valid for anything else.
    const DOMAIN: &'static [u8] = b"rustremote device fingerprint v1\0";
    /// Crockford base32: no I, L, O or U, so nothing is easily misread.
    const ALPHABET: &'static [u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    /// Fingerprint of `key`.
    #[must_use]
    pub fn of(key: &DevicePublicKey) -> Self {
        let mut context = digest::Context::new(&digest::SHA256);
        context.update(Self::DOMAIN);
        context.update(key.as_bytes());
        let digest = context.finish();
        let mut out = [0u8; 15];
        for (slot, byte) in out.iter_mut().zip(digest.as_ref()) {
            *slot = *byte;
        }
        Self(out)
    }

    /// The 24 base32 characters, without separators.
    fn chars(&self) -> [u8; 24] {
        let mut out = [b'0'; 24];
        let mut slots = out.iter_mut();
        // 5 bytes = 40 bits = 8 characters, exactly.
        let (chunks, _) = self.0.as_chunks::<5>();
        for chunk in chunks {
            let bits = chunk
                .iter()
                .fold(0u64, |acc, &byte| acc.wrapping_shl(8) | u64::from(byte));
            for index in (0..8u32).rev() {
                let value = bits.wrapping_shr(index.wrapping_mul(5)) & 0x1F;
                let symbol = usize::try_from(value)
                    .ok()
                    .and_then(|i| Self::ALPHABET.get(i))
                    .copied()
                    .unwrap_or(b'0');
                if let Some(slot) = slots.next() {
                    *slot = symbol;
                }
            }
        }
        out
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (n, group) in self.chars().chunks(4).enumerate() {
            if n > 0 {
                f.write_str("-")?;
            }
            for &c in group {
                fmt::Write::write_char(f, char::from(c))?;
            }
        }
        Ok(())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_identity_is_consistent() {
        let identity = DeviceIdentity::generate().unwrap();
        let certified = identity.certified_key();
        assert_eq!(certified.cert.len(), 1);
        let from_cert = peer_public_key(&certified.cert[0]).unwrap();
        assert_eq!(from_cert, identity.public_key());
    }

    #[test]
    fn identities_are_unique() {
        let a = DeviceIdentity::generate().unwrap();
        let b = DeviceIdentity::generate().unwrap();
        assert_ne!(a.public_key(), b.public_key());
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn create_then_load_returns_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data").join(IDENTITY_FILE_NAME);

        let created = DeviceIdentity::load_or_create(&path).unwrap();
        let loaded = DeviceIdentity::load(&path).unwrap();
        let again = DeviceIdentity::load_or_create(&path).unwrap();
        assert_eq!(created.public_key(), loaded.public_key());
        assert_eq!(created.public_key(), again.public_key());

        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.starts_with(b"RRID\x01"));
    }

    #[cfg(windows)]
    #[test]
    fn stored_key_is_not_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(IDENTITY_FILE_NAME);
        let pkcs8 = generate_pkcs8().unwrap();
        let file = encode_file(&pkcs8).unwrap();
        std::fs::write(&path, &*file).unwrap();

        // The 32-byte seed sits at the end of the PKCS#8 private-key field;
        // a 16-byte window of it must not appear in the file.
        let window = &pkcs8[16..32];
        assert!(!file.windows(window.len()).any(|w| w == window));
        assert!(DeviceIdentity::load(&path).is_ok());
    }

    #[test]
    fn concurrent_first_start_agrees_on_one_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(IDENTITY_FILE_NAME);
        let keys: Vec<DevicePublicKey> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| DeviceIdentity::load_or_create(&path).unwrap()))
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().unwrap().public_key())
                .collect()
        });
        let stored = DeviceIdentity::load(&path).unwrap().public_key();
        assert!(keys.iter().all(|k| *k == stored), "{keys:?}");
    }

    #[test]
    fn corrupt_files_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(IDENTITY_FILE_NAME);
        let native = Scheme::NATIVE.as_byte();
        let other = if Scheme::NATIVE == Scheme::Dpapi {
            Scheme::FilePermissions
        } else {
            Scheme::Dpapi
        }
        .as_byte();

        for (bytes, expected) in [
            (b"RR".to_vec(), "truncated file"),
            (
                b"XXXX\x01\x01abc".to_vec(),
                "not a RustRemote identity file",
            ),
            (
                vec![b'R', b'R', b'I', b'D', 9, native],
                "unsupported format version",
            ),
            (b"RRID\x01".to_vec(), "truncated file"),
            (
                vec![b'R', b'R', b'I', b'D', 1, 77],
                "unknown protection scheme",
            ),
            (
                vec![b'R', b'R', b'I', b'D', 1, other],
                "protected with a scheme this platform cannot read",
            ),
        ] {
            std::fs::write(&path, &bytes).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            match DeviceIdentity::load(&path) {
                Err(IdentityError::Corrupt { reason, .. }) => assert_eq!(reason, expected),
                other => panic!("{bytes:?}: expected Corrupt({expected}), got {other:?}"),
            }
        }
    }

    #[test]
    fn garbage_key_is_rejected() {
        assert!(matches!(
            DeviceIdentity::from_pkcs8(b"definitely not pkcs8"),
            Err(IdentityError::InvalidKey)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn tampered_file_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(IDENTITY_FILE_NAME);
        DeviceIdentity::load_or_create(&path).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        if let Some(last) = bytes.last_mut() {
            *last ^= 0x01;
        }
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            DeviceIdentity::load(&path),
            Err(IdentityError::Unprotect { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn world_readable_key_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(IDENTITY_FILE_NAME);
        DeviceIdentity::load_or_create(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            DeviceIdentity::load(&path),
            Err(IdentityError::Corrupt { .. })
        ));
    }

    #[test]
    fn fingerprint_format() {
        let fp = Fingerprint::of(&DevicePublicKey([7; 32])).to_string();
        assert_eq!(fp.len(), 29);
        let groups: Vec<&str> = fp.split('-').collect();
        assert_eq!(groups.len(), 6);
        assert!(groups.iter().all(|g| g.len() == 4));
        assert!(
            fp.bytes()
                .all(|c| c == b'-' || Fingerprint::ALPHABET.contains(&c))
        );
        assert_eq!(fp, Fingerprint::of(&DevicePublicKey([7; 32])).to_string());
    }

    #[test]
    fn base32_bit_order() {
        // 0x08 0x42 0x10 0x84 0x21 = 00001 00001 00001 ... -> "11111111".
        let mut raw = [0u8; 15];
        raw[..5].copy_from_slice(&[0x08, 0x42, 0x10, 0x84, 0x21]);
        let text = Fingerprint(raw).to_string();
        assert!(text.starts_with("1111-1111-0000"), "{text}");
        // All ones -> 'Z' (31) everywhere.
        assert_eq!(
            Fingerprint([0xFF; 15]).to_string(),
            "ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ"
        );
    }

    #[test]
    fn debug_never_shows_secrets() {
        let identity = DeviceIdentity::generate().unwrap();
        let text = format!("{identity:?}");
        assert!(text.contains(&identity.public_key().to_string()));
        assert!(!text.contains("certified"));
    }
}
