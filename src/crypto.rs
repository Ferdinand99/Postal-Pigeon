//! Secrets and sealing.
//!
//! * Every credential is random, URL-safe and prefixed (`hrk_`, `hrd_`,
//!   `hrm_`, `hrh_`). The relay stores only the SHA-256 of the ones clients
//!   present and compares in constant time.
//! * Device tokens must be usable, so they are sealed at rest with AES-256-GCM.
//!   The key comes from a file (never from the database), has an id that is
//!   stored with every sealed token, and old keys can stay configured while the
//!   relay re-seals under the current one.
//! * The HMAC key (challenges and token fingerprints) comes from a file too.

use std::fmt;
use std::path::Path;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::digest;
use aws_lc_rs::hkdf::{HKDF_SHA256, Salt};
use aws_lc_rs::hmac;
use aws_lc_rs::rand;
use zeroize::Zeroizing;

use crate::util::{b64, b64_decode, random_bytes};

pub const PREFIX_INSTANCE: &str = "hrk_";
pub const PREFIX_DEVICE: &str = "hrd_";
pub const PREFIX_MANAGE: &str = "hrm_";
pub const PREFIX_HANDLE: &str = "hrh_";

/// Length of a public id (8 random bytes, base64).
const ID_LEN: usize = 11;
/// Length of a secret (32 random bytes, base64).
const SECRET_LEN: usize = 43;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = digest::digest(&digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// Constant-time equality of two byte strings.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    verify_slices_are_equal(a, b).is_ok()
}

/// A secret with a public id inside it (instance credentials and handles).
#[derive(Debug, Clone)]
pub struct IdSecret {
    /// The whole secret as given to the client, prefix included.
    pub full: String,
    /// The public id (looked up in the database, shown for revocation).
    pub id: String,
    /// SHA-256 of `full`, the only form the relay stores.
    pub hash: [u8; 32],
}

/// A new `prefix + id + secret`.
pub fn new_id_secret(prefix: &str) -> IdSecret {
    let id = b64(&random_bytes::<8>());
    let secret = b64(&random_bytes::<32>());
    let full = format!("{prefix}{id}{secret}");
    let hash = sha256(full.as_bytes());
    IdSecret { full, id, hash }
}

/// A new secret for an existing public id (credential rotation).
pub fn new_secret_for(prefix: &str, id: &str) -> IdSecret {
    let secret = b64(&random_bytes::<32>());
    let full = format!("{prefix}{id}{secret}");
    let hash = sha256(full.as_bytes());
    IdSecret {
        full,
        id: id.to_string(),
        hash,
    }
}

/// Splits a presented `prefix + id + secret` without trusting it: the id and
/// the hash, or `None` for anything of the wrong shape.
pub fn parse_id_secret(prefix: &str, presented: &str) -> Option<(String, [u8; 32])> {
    let rest = presented.strip_prefix(prefix)?;
    if rest.len() != ID_LEN + SECRET_LEN || !rest.bytes().all(is_b64_char) {
        return None;
    }
    Some((rest[..ID_LEN].to_string(), sha256(presented.as_bytes())))
}

fn is_b64_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-' || c == b'_'
}

/// A new device id (`hrd_` + 16 random bytes). Not secret.
pub fn new_device_id() -> String {
    format!("{PREFIX_DEVICE}{}", b64(&random_bytes::<16>()))
}

/// Whether `s` looks like a device id.
pub fn is_device_id(s: &str) -> bool {
    s.strip_prefix(PREFIX_DEVICE)
        .is_some_and(|r| r.len() == 22 && r.bytes().all(is_b64_char))
}

/// Whether `s` looks like a public handle id.
pub fn is_handle_id(s: &str) -> bool {
    s.len() == ID_LEN && s.bytes().all(is_b64_char)
}

/// A new manage key and its hash.
pub fn new_manage_key() -> (String, [u8; 32]) {
    let key = format!("{PREFIX_MANAGE}{}", b64(&random_bytes::<32>()));
    let hash = sha256(key.as_bytes());
    (key, hash)
}

/// The hash of a presented manage key, or `None` if it has the wrong shape.
pub fn parse_manage_key(presented: &str) -> Option<[u8; 32]> {
    let rest = presented.strip_prefix(PREFIX_MANAGE)?;
    if rest.len() != SECRET_LEN || !rest.bytes().all(is_b64_char) {
        return None;
    }
    Some(sha256(presented.as_bytes()))
}

/// Why a key file couldn't be used.
#[derive(Debug)]
pub struct KeyError(pub String);

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for KeyError {}

/// Refuses a key file that other users can read or write (mode other than
/// 0400 or 0600 on Unix). A key everybody can read is not a key.
pub fn check_key_mode(path: &Path) -> Result<(), KeyError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let meta = std::fs::metadata(path)
            .map_err(|e| KeyError(format!("can't read {}: {e}", path.display())))?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(KeyError(format!(
                "{} has mode {mode:04o}, which other users can use; run chmod 0400 on it",
                path.display()
            )));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Reads a key file: 64 hex characters, or URL-safe base64, for at least 32
/// bytes. Refuses a file other users can read. The bytes are wiped from memory
/// when dropped.
pub fn read_key_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    check_key_mode(path)?;
    let text = Zeroizing::new(
        std::fs::read_to_string(path)
            .map_err(|e| KeyError(format!("can't read {}: {e}", path.display())))?,
    );
    let text = text.trim();
    let bytes = hex::decode(text)
        .ok()
        .or_else(|| b64_decode(text))
        .ok_or_else(|| KeyError(format!("{} is not hex or base64", path.display())))?;
    let bytes = Zeroizing::new(bytes);
    if bytes.len() < 32 {
        return Err(KeyError(format!(
            "{} holds fewer than 32 bytes",
            path.display()
        )));
    }
    Ok(bytes)
}

/// A fresh key as 64 hex characters, for `postal-pigeon keygen`.
pub fn generate_key_hex() -> String {
    hex::encode(random_bytes::<32>())
}

const SEAL_SALT: &[u8] = b"postal-pigeon/seal/v1";
const HMAC_DOMAIN_FP: &[u8] = b"postal-pigeon/token-fingerprint/v1";
const HMAC_DOMAIN_CHALLENGE: &[u8] = b"postal-pigeon/challenge/v1";
const HMAC_DOMAIN_COLLAPSE: &[u8] = b"postal-pigeon/collapse/v1";

/// One sealing key and its id.
pub struct SealKey {
    id: String,
    key: LessSafeKey,
}

impl SealKey {
    /// Derives the AES-256-GCM key from the key file's bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let id = hex::encode(
            &sha256(&[b"postal-pigeon/seal-key-id/v1".as_slice(), bytes].concat())[..4],
        );
        let prk = Salt::new(HKDF_SHA256, SEAL_SALT).extract(bytes);
        let info = [b"device-token".as_slice()];
        let okm = prk
            .expand(&info, &AES_256_GCM)
            .expect("HKDF can expand to one AES-256 key");
        SealKey {
            id,
            key: LessSafeKey::new(UnboundKey::from(okm)),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }
}

impl fmt::Debug for SealKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealKey")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// Why a sealed value didn't open.
#[derive(Debug, PartialEq, Eq)]
pub enum OpenError {
    /// No configured key has that id.
    UnknownKey,
    /// Malformed, tampered with, or sealed for another record.
    Unreadable,
}

/// All the relay's long-lived keys.
#[derive(Debug)]
pub struct Keys {
    hmac: hmac::Key,
    current: SealKey,
    old: Vec<SealKey>,
}

impl Keys {
    pub fn new(hmac_bytes: &[u8], seal_bytes: &[u8], old_seal: &[&[u8]]) -> Self {
        Keys {
            hmac: hmac::Key::new(hmac::HMAC_SHA256, hmac_bytes),
            current: SealKey::from_bytes(seal_bytes),
            old: old_seal.iter().map(|b| SealKey::from_bytes(b)).collect(),
        }
    }

    /// Random keys that live only as long as the process. For tests.
    pub fn ephemeral() -> Self {
        Keys::new(&random_bytes::<32>(), &random_bytes::<32>(), &[])
    }

    pub fn current_seal_id(&self) -> &str {
        self.current.id()
    }

    fn find(&self, id: &str) -> Option<&SealKey> {
        if self.current.id == id {
            return Some(&self.current);
        }
        self.old.iter().find(|k| k.id == id)
    }

    /// Seals `plaintext` under the current key. `aad` (the record's id) binds
    /// the value to its record. Returns the key id and `b64(nonce ‖ ct ‖ tag)`.
    pub fn seal(&self, plaintext: &[u8], aad: &str) -> (String, String) {
        let mut nonce = [0u8; NONCE_LEN];
        rand::fill(&mut nonce).expect("the system's random source");
        let mut buf = plaintext.to_vec();
        self.current
            .key
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad.as_bytes()),
                &mut buf,
            )
            .expect("AES-GCM seals any short value");
        let mut raw = Vec::with_capacity(NONCE_LEN + buf.len());
        raw.extend_from_slice(&nonce);
        raw.extend_from_slice(&buf);
        (self.current.id.clone(), b64(&raw))
    }

    /// Opens what [`Keys::seal`] sealed, under whichever configured key sealed it.
    pub fn open(&self, key_id: &str, sealed: &str, aad: &str) -> Result<Vec<u8>, OpenError> {
        let key = self.find(key_id).ok_or(OpenError::UnknownKey)?;
        let raw = b64_decode(sealed).ok_or(OpenError::Unreadable)?;
        if raw.len() < NONCE_LEN + 16 {
            return Err(OpenError::Unreadable);
        }
        let (nonce, rest) = raw.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce).map_err(|_| OpenError::Unreadable)?;
        let mut buf = rest.to_vec();
        let plain = key
            .key
            .open_in_place(nonce, Aad::from(aad.as_bytes()), &mut buf)
            .map_err(|_| OpenError::Unreadable)?;
        Ok(plain.to_vec())
    }

    /// Fingerprint of a device token: only for telling that two records hold
    /// the same token (uniqueness), never reversible.
    pub fn token_fingerprint(&self, token: &str) -> [u8; 32] {
        self.mac(&[HMAC_DOMAIN_FP, token.as_bytes()])
    }

    /// The collapse id Apple sees for an alert: a keyed hash of the handle and
    /// the instance's `collapse` value, so that two servers that share a device
    /// (through different handles) can't replace each other's notifications by
    /// choosing the same value, and nothing readable leaves the relay.
    pub fn scoped_collapse(&self, scope: &str, collapse: &str) -> String {
        let mac = self.mac(&[
            HMAC_DOMAIN_COLLAPSE,
            scope.as_bytes(),
            &[0],
            collapse.as_bytes(),
        ]);
        b64(&mac[..18])
    }

    /// MAC over a challenge's body.
    pub fn challenge_mac(&self, body: &[u8]) -> [u8; 32] {
        self.mac(&[HMAC_DOMAIN_CHALLENGE, body])
    }

    fn mac(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut ctx = hmac::Context::with_key(&self.hmac);
        for p in parts {
            ctx.update(p);
        }
        let tag = ctx.sign();
        let mut out = [0u8; 32];
        out.copy_from_slice(tag.as_ref());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_secret_round_trip() {
        let s = new_id_secret(PREFIX_INSTANCE);
        assert!(s.full.starts_with("hrk_"));
        assert_eq!(s.full.len(), 4 + ID_LEN + SECRET_LEN);
        let (id, hash) = parse_id_secret(PREFIX_INSTANCE, &s.full).unwrap();
        assert_eq!(id, s.id);
        assert!(ct_eq(&hash, &s.hash));
        assert!(parse_id_secret(PREFIX_HANDLE, &s.full).is_none());
        assert!(parse_id_secret(PREFIX_INSTANCE, "hrk_short").is_none());
        let bad = format!("{}!", &s.full[..s.full.len() - 1]);
        assert!(parse_id_secret(PREFIX_INSTANCE, &bad).is_none());
        let rotated = new_secret_for(PREFIX_INSTANCE, &s.id);
        assert_eq!(rotated.id, s.id);
        assert_ne!(rotated.hash, s.hash);
    }

    #[test]
    fn device_ids_and_manage_keys() {
        let d = new_device_id();
        assert!(is_device_id(&d));
        assert!(!is_device_id("hrd_x"));
        let (k, h) = new_manage_key();
        assert_eq!(parse_manage_key(&k), Some(h));
        assert!(parse_manage_key("hrm_nope").is_none());
    }

    #[test]
    fn sealing_binds_to_the_record_and_the_key() {
        let keys = Keys::ephemeral();
        let (kid, sealed) = keys.seal(b"abcdef", "hrd_one");
        assert_eq!(keys.open(&kid, &sealed, "hrd_one").unwrap(), b"abcdef");
        assert_eq!(
            keys.open(&kid, &sealed, "hrd_two"),
            Err(OpenError::Unreadable)
        );
        assert_eq!(
            keys.open("ffffffff", &sealed, "hrd_one"),
            Err(OpenError::UnknownKey)
        );
        let other = Keys::ephemeral();
        assert!(
            other
                .open(other.current_seal_id(), &sealed, "hrd_one")
                .is_err()
        );
        // Two seals of one value differ (fresh nonce).
        assert_ne!(sealed, keys.seal(b"abcdef", "hrd_one").1);
    }

    #[test]
    fn old_keys_still_open() {
        let old = random_bytes::<32>();
        let hmac_key = random_bytes::<32>();
        let before = Keys::new(&hmac_key, &old, &[]);
        let (kid, sealed) = before.seal(b"tok", "d");
        let after = Keys::new(&hmac_key, &random_bytes::<32>(), &[old.as_slice()]);
        assert_ne!(after.current_seal_id(), kid);
        assert_eq!(after.open(&kid, &sealed, "d").unwrap(), b"tok");
    }

    #[test]
    fn collapse_ids_are_scoped_to_the_handle() {
        let k = Keys::ephemeral();
        let a = k.scoped_collapse("handle-a", "incident-1");
        assert_eq!(a, k.scoped_collapse("handle-a", "incident-1"));
        assert_ne!(a, k.scoped_collapse("handle-b", "incident-1"));
        assert_ne!(a, k.scoped_collapse("handle-a", "incident-2"));
        assert!(!a.contains("incident"));
        assert!(a.len() <= 30);
        // The scope and the value can't be shifted into each other.
        assert_ne!(k.scoped_collapse("ab", "c"), k.scoped_collapse("a", "bc"));
    }

    #[cfg(unix)]
    #[test]
    fn key_files_must_be_private() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("pp-key-{}", crate::util::uuid_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("k");
        std::fs::write(&path, format!("{}\n", generate_key_hex())).unwrap();
        for (mode, ok) in [
            (0o600, true),
            (0o400, true),
            (0o640, false),
            (0o644, false),
            (0o604, false),
        ] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(read_key_file(&path).is_ok(), ok, "mode {mode:o}");
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_key_file(&path).unwrap().len(), 32);
        std::fs::write(&path, "abcd").unwrap();
        assert!(read_key_file(&path).is_err(), "too short");
        let _ = std::fs::remove_dir_all(dir);
    }
    #[test]
    fn fingerprints_are_keyed() {
        let a = Keys::ephemeral();
        let b = Keys::ephemeral();
        assert_eq!(a.token_fingerprint("t"), a.token_fingerprint("t"));
        assert_ne!(a.token_fingerprint("t"), a.token_fingerprint("u"));
        assert_ne!(a.token_fingerprint("t"), b.token_fingerprint("t"));
    }
}
