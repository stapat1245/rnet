//! Persistent cryptographic identity for a mynet node.
//!
//! Identity answers "who is this peer?". It is a Curve25519/X25519 keypair,
//! the same construction WireGuard uses. A UDP endpoint or virtual IP is not
//! identity and is not stored here.
//!
//! The private key never leaves this crate's storage helpers. Callers that
//! print identity (the CLI) receive only the public key and the derived
//! peer ID.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};
use zeroize::Zeroize;

/// Current on-disk schema. Bump when the file format changes.
pub const SCHEMA_VERSION: u32 = 1;

/// Required permission bits for an identity file: owner read/write only.
pub const IDENTITY_FILE_MODE: u32 = 0o600;

const PRIVATE_KEY_LEN: usize = 32;
const PUBLIC_KEY_LEN: usize = 32;
const PEER_ID_LEN: usize = 16;

/// Stable fingerprint of a public key (first 16 bytes of SHA-256, hex).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerId([u8; PEER_ID_LEN]);

impl PeerId {
    /// Derive a peer ID from a 32-byte X25519 public key.
    pub fn from_public_key_bytes(public_key: &[u8; PUBLIC_KEY_LEN]) -> Self {
        let digest = Sha256::digest(public_key);
        let mut id = [0u8; PEER_ID_LEN];
        id.copy_from_slice(&digest[..PEER_ID_LEN]);
        PeerId(id)
    }

    pub fn as_bytes(&self) -> &[u8; PEER_ID_LEN] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, IdentityError> {
        let bytes = hex::decode(s.trim()).map_err(|_| IdentityError::Malformed {
            path: PathBuf::from("<peer-id>"),
            reason: "peer id is not valid hex".to_string(),
        })?;
        if bytes.len() != PEER_ID_LEN {
            return Err(IdentityError::Malformed {
                path: PathBuf::from("<peer-id>"),
                reason: format!("peer id must be {PEER_ID_LEN} bytes ({} hex chars)", PEER_ID_LEN * 2),
            });
        }
        let mut id = [0u8; PEER_ID_LEN];
        id.copy_from_slice(&bytes);
        Ok(PeerId(id))
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PeerId").field(&self.to_hex()).finish()
    }
}

/// A node's X25519 public key. WireGuard-compatible (32 bytes, standard base64).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; PUBLIC_KEY_LEN]);

impl PublicKey {
    pub fn from_bytes(bytes: [u8; PUBLIC_KEY_LEN]) -> Self {
        PublicKey(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.0
    }

    pub fn to_base64(&self) -> String {
        BASE64.encode(self.0)
    }

    pub fn from_base64(s: &str) -> Result<Self, IdentityError> {
        decode_key_base64(s, "<public-key>").map(PublicKey)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base64())
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PublicKey").field(&self.to_base64()).finish()
    }
}

/// Local cryptographic identity. The private key is zeroized on drop.
pub struct Identity {
    private: [u8; PRIVATE_KEY_LEN],
    public: PublicKey,
    peer_id: PeerId,
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.private.zeroize();
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("peer_id", &self.peer_id)
            .field("public_key", &self.public)
            .finish()
    }
}

impl Identity {
    /// Generate a new random identity.
    pub fn generate() -> Self {
        let secret = StaticSecret::random();
        Self::from_static_secret(&secret)
    }

    /// Reconstruct identity from raw private key bytes (clamped by X25519).
    pub fn from_private_bytes(bytes: [u8; PRIVATE_KEY_LEN]) -> Self {
        let secret = StaticSecret::from(bytes);
        Self::from_static_secret(&secret)
    }

    fn from_static_secret(secret: &StaticSecret) -> Self {
        let public = PublicKey::from_bytes(*X25519Public::from(secret).as_bytes());
        let peer_id = PeerId::from_public_key_bytes(public.as_bytes());
        Identity {
            private: secret.to_bytes(),
            public,
            peer_id,
        }
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn public_key(&self) -> PublicKey {
        self.public
    }

    /// Raw private key bytes for later WireGuard configuration.
    ///
    /// Do not log or print this. The CLI must not display it by default.
    pub fn private_key_bytes(&self) -> &[u8; PRIVATE_KEY_LEN] {
        &self.private
    }

    /// Persist the identity. Refuses to overwrite unless `force` is true.
    pub fn save_to(&self, path: &Path, force: bool) -> Result<(), IdentityError> {
        if path.exists() && !force {
            return Err(IdentityError::AlreadyExists {
                path: path.to_path_buf(),
            });
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                ensure_config_dir(parent)?;
            }
        }

        let mut file = FileOnDisk {
            schema_version: SCHEMA_VERSION,
            private_key: BASE64.encode(self.private),
            public_key: self.public.to_base64(),
            peer_id: self.peer_id.to_hex(),
        };
        let serialized = toml::to_string_pretty(&file).map_err(|source| IdentityError::Serialize {
            path: path.to_path_buf(),
            source,
        })?;
        file.private_key.zeroize();
        let serialized = format!(
            "# mynet identity. Never share private_key. File mode must be 0600.\n{serialized}\n"
        );

        let tmp = tmp_path(path);
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(IDENTITY_FILE_MODE);
        let mut f = opts.open(&tmp).map_err(|source| IdentityError::Io {
            path: tmp.clone(),
            source,
        })?;
        f.write_all(serialized.as_bytes()).map_err(|source| IdentityError::Io {
            path: tmp.clone(),
            source,
        })?;
        f.sync_all().map_err(|source| IdentityError::Io {
            path: tmp.clone(),
            source,
        })?;
        drop(f);
        fs::rename(&tmp, path).map_err(|source| IdentityError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        chmod(path, IDENTITY_FILE_MODE).map_err(|source| IdentityError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(())
    }

    /// Load an identity and verify derived public key and peer ID match the file.
    pub fn load_from(path: &Path) -> Result<Self, IdentityError> {
        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(IdentityError::NotFound {
                    path: path.to_path_buf(),
                });
            }
            Err(source) => {
                return Err(IdentityError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(IdentityError::InsecurePermissions {
                path: path.to_path_buf(),
                mode,
            });
        }

        let contents = fs::read_to_string(path).map_err(|source| IdentityError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let parsed: FileOnDisk = toml::from_str(&contents).map_err(|_| IdentityError::Malformed {
            path: path.to_path_buf(),
            reason: "file is not valid identity TOML".to_string(),
        })?;

        if parsed.schema_version != SCHEMA_VERSION {
            return Err(IdentityError::Malformed {
                path: path.to_path_buf(),
                reason: format!(
                    "unsupported schema_version {} (expected {SCHEMA_VERSION})",
                    parsed.schema_version
                ),
            });
        }

        let private_bytes = decode_key_base64(&parsed.private_key, path)?;
        let identity = Identity::from_private_bytes(private_bytes);

        let stored_public = PublicKey::from_base64(&parsed.public_key).map_err(|_| {
            IdentityError::Malformed {
                path: path.to_path_buf(),
                reason: "public_key is not valid base64 or the wrong length".to_string(),
            }
        })?;
        if stored_public != identity.public {
            return Err(IdentityError::Malformed {
                path: path.to_path_buf(),
                reason: "stored public_key does not match the private key".to_string(),
            });
        }

        let stored_id = PeerId::from_hex(&parsed.peer_id).map_err(|_| IdentityError::Malformed {
            path: path.to_path_buf(),
            reason: "peer_id is not valid hex or the wrong length".to_string(),
        })?;
        if stored_id != identity.peer_id {
            return Err(IdentityError::Malformed {
                path: path.to_path_buf(),
                reason: "stored peer_id does not match the public key".to_string(),
            });
        }

        Ok(identity)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct FileOnDisk {
    schema_version: u32,
    private_key: String,
    public_key: String,
    peer_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("identity file not found at {}; run `mynet init`", .path.display())]
    NotFound { path: PathBuf },
    #[error(
        "identity file {} has insecure permissions {mode:#o}; expected {IDENTITY_FILE_MODE:#o}",
        .path.display()
    )]
    InsecurePermissions { path: PathBuf, mode: u32 },
    #[error("identity file {} is malformed: {reason}", .path.display())]
    Malformed { path: PathBuf, reason: String },
    #[error("identity file {} already exists; pass --force to overwrite", .path.display())]
    AlreadyExists { path: PathBuf },
    #[error("failed to access {}: {source}", .path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to serialize identity for {}: {source}", .path.display())]
    Serialize {
        path: PathBuf,
        #[source]
        source: toml::ser::Error,
    },
}

fn decode_key_base64(s: &str, path_label: impl AsRef<Path>) -> Result<[u8; PRIVATE_KEY_LEN], IdentityError> {
    let path = path_label.as_ref().to_path_buf();
    let bytes = BASE64.decode(s.trim()).map_err(|_| IdentityError::Malformed {
        path: path.clone(),
        reason: "key is not valid base64".to_string(),
    })?;
    if bytes.len() != PRIVATE_KEY_LEN {
        return Err(IdentityError::Malformed {
            path,
            reason: format!("key must be {PRIVATE_KEY_LEN} bytes"),
        });
    }
    let mut arr = [0u8; PRIVATE_KEY_LEN];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn chmod(path: &Path, mode: u32) -> io::Result<()> {
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(mode);
    fs::set_permissions(path, perms)
}

fn tmp_path(path: &Path) -> PathBuf {
    match path.file_name() {
        Some(name) => {
            let mut tmp_name = name.to_os_string();
            tmp_name.push(".tmp");
            path.with_file_name(tmp_name)
        }
        None => path.with_extension("tmp"),
    }
}

fn ensure_config_dir(dir: &Path) -> Result<(), IdentityError> {
    if !dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|source| IdentityError::Io {
                path: dir.to_path_buf(),
                source,
            })?;
        return Ok(());
    }
    chmod(dir, 0o700).map_err(|source| IdentityError::Io {
        path: dir.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_identity_path() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.toml");
        (dir, path)
    }

    #[test]
    fn generate_and_reload() {
        let (_dir, path) = temp_identity_path();
        let original = Identity::generate();
        original.save_to(&path, false).unwrap();
        let loaded = Identity::load_from(&path).unwrap();
        assert_eq!(original.peer_id(), loaded.peer_id());
        assert_eq!(original.public_key(), loaded.public_key());
        assert_eq!(original.private_key_bytes(), loaded.private_key_bytes());
    }

    #[test]
    fn same_private_key_same_public_key() {
        let bytes = [7u8; 32];
        let a = Identity::from_private_bytes(bytes);
        let b = Identity::from_private_bytes(bytes);
        assert_eq!(a.public_key(), b.public_key());
        assert_eq!(a.peer_id(), b.peer_id());
    }

    #[test]
    fn different_keys_differ() {
        let a = Identity::generate();
        let b = Identity::generate();
        assert_ne!(a.public_key(), b.public_key());
        assert_ne!(a.peer_id(), b.peer_id());
    }

    #[test]
    fn missing_file() {
        let path = PathBuf::from("/tmp/mynet-does-not-exist-identity.toml");
        match Identity::load_from(&path) {
            Err(IdentityError::NotFound { .. }) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn malformed_toml() {
        let (_dir, path) = temp_identity_path();
        fs::write(&path, "this is not toml [[[").unwrap();
        chmod(&path, IDENTITY_FILE_MODE).unwrap();
        match Identity::load_from(&path) {
            Err(IdentityError::Malformed { reason, .. }) => {
                assert!(reason.contains("TOML"), "{reason}");
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn malformed_short_key() {
        let (_dir, path) = temp_identity_path();
        let body = r#"
schema_version = 1
private_key = "AAAA"
public_key = "AAAA"
peer_id = "00000000000000000000000000000000"
"#;
        fs::write(&path, body).unwrap();
        chmod(&path, IDENTITY_FILE_MODE).unwrap();
        match Identity::load_from(&path) {
            Err(IdentityError::Malformed { .. }) => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn mismatched_public_key_is_corrupt() {
        let (_dir, path) = temp_identity_path();
        let identity = Identity::generate();
        identity.save_to(&path, false).unwrap();
        let mut parsed: FileOnDisk = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        parsed.public_key = Identity::generate().public_key().to_base64();
        fs::write(&path, toml::to_string(&parsed).unwrap()).unwrap();
        chmod(&path, IDENTITY_FILE_MODE).unwrap();
        match Identity::load_from(&path) {
            Err(IdentityError::Malformed { reason, .. }) => {
                assert!(reason.contains("public_key"), "{reason}");
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn insecure_permissions_rejected() {
        let (_dir, path) = temp_identity_path();
        let identity = Identity::generate();
        identity.save_to(&path, false).unwrap();
        chmod(&path, 0o644).unwrap();
        match Identity::load_from(&path) {
            Err(IdentityError::InsecurePermissions { mode, .. }) => {
                assert_eq!(mode, 0o644);
            }
            other => panic!("expected InsecurePermissions, got {other:?}"),
        }
    }

    #[test]
    fn refuse_overwrite_without_force() {
        let (_dir, path) = temp_identity_path();
        let first = Identity::generate();
        first.save_to(&path, false).unwrap();
        let second = Identity::generate();
        match second.save_to(&path, false) {
            Err(IdentityError::AlreadyExists { .. }) => {}
            other => panic!("expected AlreadyExists, got {other:?}"),
        }
        second.save_to(&path, true).unwrap();
        let loaded = Identity::load_from(&path).unwrap();
        assert_eq!(loaded.public_key(), second.public_key());
    }

    #[test]
    fn saved_file_is_0600() {
        let (_dir, path) = temp_identity_path();
        Identity::generate().save_to(&path, false).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn debug_does_not_include_private_key() {
        let identity = Identity::generate();
        let debug = format!("{identity:?}");
        assert!(debug.contains("PeerId"));
        assert!(!debug.contains(&BASE64.encode(identity.private_key_bytes())));
        assert!(!debug.to_lowercase().contains("private"));
    }

    #[test]
    fn peer_id_is_stable_hex() {
        let identity = Identity::from_private_bytes([1u8; 32]);
        let hex = identity.peer_id().to_hex();
        assert_eq!(hex.len(), 32);
        assert_eq!(hex, identity.peer_id().to_string());
        assert_eq!(PeerId::from_hex(&hex).unwrap(), identity.peer_id());
    }
}
