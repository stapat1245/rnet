//! Local trusted-peer list (control plane).
//!
//! **Trusted** means: an operator explicitly added this peer's public key to
//! `peers.toml`. That is a local policy decision. It is not authentication of
//! live traffic. An IP address, hostname, UDP endpoint, or claimed name is
//! never identity. Cryptographic proof of the matching private key is required
//! before overlay packets are accepted; that proof comes from WireGuard in
//! later phases, not from this file.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use mynet_identity::{PeerId, PublicKey};
use serde::{Deserialize, Serialize};

pub const PEERS_FILE_MODE: u32 = 0o600;
const SCHEMA_VERSION: u32 = 1;

/// Connection state for a peer. Persisted value is `Disconnected` until
/// later phases implement a live state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerState {
    Disconnected,
    Discovering,
    Connecting,
    Direct,
    Relaying,
    Failed,
}

impl PeerState {
    pub fn as_str(self) -> &'static str {
        match self {
            PeerState::Disconnected => "disconnected",
            PeerState::Discovering => "discovering",
            PeerState::Connecting => "connecting",
            PeerState::Direct => "direct",
            PeerState::Relaying => "relaying",
            PeerState::Failed => "failed",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "disconnected" => Some(PeerState::Disconnected),
            "discovering" => Some(PeerState::Discovering),
            "connecting" => Some(PeerState::Connecting),
            "direct" => Some(PeerState::Direct),
            "relaying" => Some(PeerState::Relaying),
            "failed" => Some(PeerState::Failed),
            _ => None,
        }
    }
}

impl std::fmt::Display for PeerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Default for PeerState {
    fn default() -> Self {
        PeerState::Disconnected
    }
}

/// A peer this node is willing to talk to, identified by public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    pub id: PeerId,
    pub public_key: PublicKey,
    pub virtual_ip: Ipv4Addr,
    pub endpoint: Option<SocketAddr>,
    pub name: Option<String>,
    pub state: PeerState,
}

impl Peer {
    pub fn new(
        public_key: PublicKey,
        virtual_ip: Ipv4Addr,
        endpoint: Option<SocketAddr>,
        name: Option<String>,
    ) -> Result<Self, PeerError> {
        validate_virtual_ip(virtual_ip)?;
        if let Some(addr) = endpoint {
            if !addr.is_ipv4() {
                return Err(PeerError::Ipv6Endpoint);
            }
        }
        let name = normalize_name(name)?;
        Ok(Peer {
            id: PeerId::from_public_key_bytes(public_key.as_bytes()),
            public_key,
            virtual_ip,
            endpoint,
            name,
            state: PeerState::Disconnected,
        })
    }

    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| self.id.to_hex()[..8].to_string())
    }
}

/// On-disk trusted peer list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerList {
    peers: Vec<Peer>,
}

impl PeerList {
    pub fn new() -> Self {
        PeerList { peers: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    pub fn peers(&self) -> &[Peer] {
        &self.peers
    }

    /// Overlay IP → UDP endpoint for peers that have an endpoint configured.
    pub fn udp_routes(&self) -> Vec<(Ipv4Addr, SocketAddr)> {
        self.peers
            .iter()
            .filter_map(|p| p.endpoint.map(|endpoint| (p.virtual_ip, endpoint)))
            .collect()
    }

    pub fn load_from(path: &Path) -> Result<Self, PeerError> {
        match fs::metadata(path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(PeerList::new()),
            Err(source) => {
                return Err(PeerError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
            Ok(meta) => {
                let mode = meta.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    return Err(PeerError::InsecurePermissions {
                        path: path.to_path_buf(),
                        mode,
                    });
                }
            }
        }
        let text = fs::read_to_string(path).map_err(|source| PeerError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let parsed: FileOnDisk = toml::from_str(&text).map_err(|_| PeerError::Malformed {
            path: path.to_path_buf(),
            reason: "file is not valid peers TOML".to_string(),
        })?;
        if parsed.schema_version != SCHEMA_VERSION {
            return Err(PeerError::Malformed {
                path: path.to_path_buf(),
                reason: format!(
                    "unsupported schema_version {} (expected {SCHEMA_VERSION})",
                    parsed.schema_version
                ),
            });
        }
        let mut list = PeerList::new();
        for record in parsed.peers {
            let peer = record.into_peer(path)?;
            list.add(peer)?;
        }
        Ok(list)
    }

    pub fn save_to(&self, path: &Path) -> Result<(), PeerError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|source| PeerError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
        }
        let file = FileOnDisk {
            schema_version: SCHEMA_VERSION,
            peers: self.peers.iter().map(FilePeer::from_peer).collect(),
        };
        let serialized = toml::to_string_pretty(&file).map_err(|source| PeerError::Serialize {
            path: path.to_path_buf(),
            source,
        })?;
        let serialized = format!(
            "# mynet trusted peers. Public keys are trust decisions.\n{serialized}\n"
        );

        let tmp = match path.file_name() {
            Some(name) => {
                let mut tmp_name = name.to_os_string();
                tmp_name.push(".tmp");
                path.with_file_name(tmp_name)
            }
            None => path.with_extension("tmp"),
        };
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(PEERS_FILE_MODE);
        let mut f = opts.open(&tmp).map_err(|source| PeerError::Io {
            path: tmp.clone(),
            source,
        })?;
        f.write_all(serialized.as_bytes()).map_err(|source| PeerError::Io {
            path: tmp.clone(),
            source,
        })?;
        f.sync_all().map_err(|source| PeerError::Io {
            path: tmp.clone(),
            source,
        })?;
        drop(f);
        fs::rename(&tmp, path).map_err(|source| PeerError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let mut perms = fs::metadata(path)
            .map_err(|source| PeerError::Io {
                path: path.to_path_buf(),
                source,
            })?
            .permissions();
        perms.set_mode(PEERS_FILE_MODE);
        fs::set_permissions(path, perms).map_err(|source| PeerError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(())
    }

    pub fn add(&mut self, peer: Peer) -> Result<(), PeerError> {
        if self.peers.iter().any(|p| p.public_key == peer.public_key) {
            return Err(PeerError::DuplicatePublicKey(peer.public_key.to_base64()));
        }
        if self.peers.iter().any(|p| p.id == peer.id) {
            return Err(PeerError::DuplicatePeerId(peer.id.to_hex()));
        }
        if self.peers.iter().any(|p| p.virtual_ip == peer.virtual_ip) {
            return Err(PeerError::DuplicateVirtualIp(peer.virtual_ip));
        }
        if let Some(name) = &peer.name {
            if self.peers.iter().any(|p| p.name.as_deref() == Some(name)) {
                return Err(PeerError::DuplicateName(name.clone()));
            }
        }
        self.peers.push(peer);
        Ok(())
    }

    pub fn remove(&mut self, query: &str) -> Result<Peer, PeerError> {
        let idx = self
            .find_index(query)
            .ok_or_else(|| PeerError::NotFound(query.to_string()))?;
        Ok(self.peers.remove(idx))
    }

    pub fn get(&self, query: &str) -> Option<&Peer> {
        self.find_index(query).map(|i| &self.peers[i])
    }

    pub fn get_by_public_key(&self, public_key: &PublicKey) -> Option<&Peer> {
        self.peers.iter().find(|p| p.public_key == *public_key)
    }

    /// Apply a discovered member. Public key is identity; overlay IP is a
    /// local mapping that cannot change for a known key; endpoint is discovery.
    ///
    /// Unknown keys are rejected unless `allow_new` is set (join-token trust).
    pub fn apply_discovery(
        &mut self,
        public_key: PublicKey,
        virtual_ip: Ipv4Addr,
        endpoint: Option<SocketAddr>,
        allow_new: bool,
        name: Option<String>,
    ) -> Result<ApplyKind, PeerError> {
        if let Some(idx) = self.peers.iter().position(|p| p.public_key == public_key) {
            if self.peers[idx].virtual_ip != virtual_ip {
                return Err(PeerError::VirtualIpMismatch {
                    trusted: self.peers[idx].virtual_ip,
                    advertised: virtual_ip,
                });
            }
            if self.peers[idx].endpoint == endpoint {
                return Ok(ApplyKind::Unchanged);
            }
            self.peers[idx].endpoint = endpoint;
            return Ok(ApplyKind::EndpointUpdated);
        }
        if !allow_new {
            return Err(PeerError::UnknownPublicKey);
        }
        let peer = Peer::new(public_key, virtual_ip, endpoint, name)?;
        self.add(peer)?;
        Ok(ApplyKind::Added)
    }

    fn find_index(&self, query: &str) -> Option<usize> {
        let q = query.trim();
        self.peers.iter().position(|p| {
            p.id.to_hex() == q
                || p.public_key.to_base64() == q
                || p.name.as_deref() == Some(q)
        })
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct FileOnDisk {
    schema_version: u32,
    #[serde(default)]
    peers: Vec<FilePeer>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FilePeer {
    peer_id: String,
    public_key: String,
    virtual_ip: String,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

impl FilePeer {
    fn from_peer(peer: &Peer) -> Self {
        FilePeer {
            peer_id: peer.id.to_hex(),
            public_key: peer.public_key.to_base64(),
            virtual_ip: peer.virtual_ip.to_string(),
            endpoint: peer.endpoint.map(|e| e.to_string()),
            name: peer.name.clone(),
        }
    }

    fn into_peer(self, path: &Path) -> Result<Peer, PeerError> {
        let public_key = PublicKey::from_base64(&self.public_key).map_err(|_| PeerError::Malformed {
            path: path.to_path_buf(),
            reason: "public_key is not valid base64 or the wrong length".to_string(),
        })?;
        let virtual_ip: Ipv4Addr = self.virtual_ip.parse().map_err(|_| PeerError::Malformed {
            path: path.to_path_buf(),
            reason: format!("invalid virtual_ip {}", self.virtual_ip),
        })?;
        let endpoint = match self.endpoint {
            Some(s) => Some(parse_endpoint(&s)?),
            None => None,
        };
        let peer = Peer::new(public_key, virtual_ip, endpoint, self.name)?;
        let stored_id = PeerId::from_hex(&self.peer_id).map_err(|_| PeerError::Malformed {
            path: path.to_path_buf(),
            reason: "peer_id is not valid hex or the wrong length".to_string(),
        })?;
        if stored_id != peer.id {
            return Err(PeerError::Malformed {
                path: path.to_path_buf(),
                reason: "stored peer_id does not match the public key".to_string(),
            });
        }
        Ok(peer)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    #[error("peer file {} has insecure permissions {mode:#o}; expected {PEERS_FILE_MODE:#o}", .path.display())]
    InsecurePermissions { path: PathBuf, mode: u32 },
    #[error("peer file {} is malformed: {reason}", .path.display())]
    Malformed { path: PathBuf, reason: String },
    #[error("failed to serialize peers for {}: {source}", .path.display())]
    Serialize {
        path: PathBuf,
        #[source]
        source: toml::ser::Error,
    },
    #[error("failed to access {}: {source}", .path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("duplicate public key {0}")]
    DuplicatePublicKey(String),
    #[error("duplicate peer id {0}")]
    DuplicatePeerId(String),
    #[error("duplicate virtual IP {0}")]
    DuplicateVirtualIp(Ipv4Addr),
    #[error("duplicate peer name {0}")]
    DuplicateName(String),
    #[error("peer not found: {0}")]
    NotFound(String),
    #[error("virtual IP {0} must be a usable address in 10.42.0.0/24")]
    InvalidVirtualIp(Ipv4Addr),
    #[error("endpoint must be an IPv4 socket address (host:port)")]
    Ipv6Endpoint,
    #[error("invalid IPv4 endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("invalid peer name {0:?}; use 1-32 characters [A-Za-z0-9_-]")]
    InvalidName(String),
    #[error("unknown public key is not in the trusted peer list")]
    UnknownPublicKey,
    #[error("refusing advertised overlay IP {advertised} for a known key (trusted mapping is {trusted})")]
    VirtualIpMismatch {
        trusted: Ipv4Addr,
        advertised: Ipv4Addr,
    },
}

/// Result of applying a coordinator or manual discovery update.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyKind {
    Added,
    EndpointUpdated,
    Unchanged,
}

fn validate_virtual_ip(ip: Ipv4Addr) -> Result<(), PeerError> {
    if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() || ip.is_loopback() {
        return Err(PeerError::InvalidVirtualIp(ip));
    }
    let o = ip.octets();
    if o[0] != 10 || o[1] != 42 || o[2] != 0 || o[3] == 0 || o[3] == 255 {
        return Err(PeerError::InvalidVirtualIp(ip));
    }
    Ok(())
}

fn normalize_name(name: Option<String>) -> Result<Option<String>, PeerError> {
    match name {
        None => Ok(None),
        Some(raw) => {
            let s = raw.trim();
            if s.is_empty() {
                return Ok(None);
            }
            if s.len() > 32
                || !s
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                return Err(PeerError::InvalidName(s.to_string()));
            }
            Ok(Some(s.to_string()))
        }
    }
}

pub fn parse_endpoint(s: &str) -> Result<SocketAddr, PeerError> {
    let addr: SocketAddr = s.parse().map_err(|_| PeerError::InvalidEndpoint(s.to_string()))?;
    if !addr.is_ipv4() {
        return Err(PeerError::Ipv6Endpoint);
    }
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mynet_identity::Identity;

    fn sample_peer(ip: &str, name: Option<&str>) -> Peer {
        let identity = Identity::generate();
        Peer::new(
            identity.public_key(),
            ip.parse().unwrap(),
            None,
            name.map(|s| s.to_string()),
        )
        .unwrap()
    }

    #[test]
    fn add_list_remove_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.toml");
        let mut list = PeerList::new();
        let peer = sample_peer("10.42.0.2", Some("bob"));
        let id = peer.id;
        list.add(peer).unwrap();
        list.save_to(&path).unwrap();
        let loaded = PeerList::load_from(&path).unwrap();
        assert_eq!(loaded.peers().len(), 1);
        assert_eq!(loaded.peers()[0].id, id);
        assert_eq!(loaded.peers()[0].name.as_deref(), Some("bob"));
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let mut loaded = loaded;
        loaded.remove("bob").unwrap();
        assert!(loaded.peers().is_empty());
    }

    #[test]
    fn missing_file_is_empty_list() {
        let dir = tempfile::tempdir().unwrap();
        let list = PeerList::load_from(&dir.path().join("peers.toml")).unwrap();
        assert!(list.peers().is_empty());
    }

    #[test]
    fn duplicate_public_key_rejected() {
        let mut list = PeerList::new();
        let identity = Identity::generate();
        let a = Peer::new(identity.public_key(), "10.42.0.2".parse().unwrap(), None, None).unwrap();
        let b = Peer::new(identity.public_key(), "10.42.0.3".parse().unwrap(), None, None).unwrap();
        list.add(a).unwrap();
        assert!(matches!(list.add(b), Err(PeerError::DuplicatePublicKey(_))));
    }

    #[test]
    fn duplicate_virtual_ip_rejected() {
        let mut list = PeerList::new();
        list.add(sample_peer("10.42.0.2", Some("a"))).unwrap();
        let err = list.add(sample_peer("10.42.0.2", Some("b"))).unwrap_err();
        assert!(matches!(err, PeerError::DuplicateVirtualIp(_)));
    }

    #[test]
    fn invalid_public_key_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peers.toml");
        fs::write(
            &path,
            "schema_version = 1\n\n[[peers]]\npeer_id = \"00\"\npublic_key = \"AAAA\"\nvirtual_ip = \"10.42.0.2\"\n",
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            PeerList::load_from(&path),
            Err(PeerError::Malformed { .. })
        ));
    }

    #[test]
    fn endpoint_parse_ipv4() {
        let identity = Identity::generate();
        let peer = Peer::new(
            identity.public_key(),
            "10.42.0.2".parse().unwrap(),
            Some("203.0.113.50:51820".parse().unwrap()),
            None,
        )
        .unwrap();
        assert_eq!(peer.endpoint.unwrap().to_string(), "203.0.113.50:51820");
    }

    #[test]
    fn loopback_virtual_ip_rejected() {
        let identity = Identity::generate();
        let err = Peer::new(
            identity.public_key(),
            Ipv4Addr::LOCALHOST,
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, PeerError::InvalidVirtualIp(_)));
    }

    #[test]
    fn off_overlay_ip_rejected() {
        let identity = Identity::generate();
        let err = Peer::new(
            identity.public_key(),
            "8.8.8.8".parse().unwrap(),
            None,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, PeerError::InvalidVirtualIp(_)));
    }

    #[test]
    fn remove_unknown_peer() {
        let mut list = PeerList::new();
        assert!(matches!(list.remove("nope"), Err(PeerError::NotFound(_))));
    }

    #[test]
    fn discovery_updates_endpoint_without_changing_identity() {
        let identity = Identity::generate();
        let pk = identity.public_key();
        let mut list = PeerList::new();
        list.add(
            Peer::new(
                pk,
                "10.42.0.2".parse().unwrap(),
                Some("192.0.2.10:51820".parse().unwrap()),
                Some("bob".into()),
            )
            .unwrap(),
        )
        .unwrap();
        let kind = list
            .apply_discovery(
                pk,
                "10.42.0.2".parse().unwrap(),
                Some("203.0.113.50:51821".parse().unwrap()),
                false,
                None,
            )
            .unwrap();
        assert_eq!(kind, ApplyKind::EndpointUpdated);
        let peer = list.get("bob").unwrap();
        assert_eq!(peer.public_key, pk);
        assert_eq!(peer.virtual_ip, "10.42.0.2".parse::<Ipv4Addr>().unwrap());
        assert_eq!(peer.endpoint.unwrap().to_string(), "203.0.113.50:51821");
    }

    #[test]
    fn discovery_rejects_unknown_key_unless_join() {
        let identity = Identity::generate();
        let mut list = PeerList::new();
        let err = list
            .apply_discovery(
                identity.public_key(),
                "10.42.0.2".parse().unwrap(),
                Some("192.0.2.10:51820".parse().unwrap()),
                false,
                None,
            )
            .unwrap_err();
        assert!(matches!(err, PeerError::UnknownPublicKey));
        let kind = list
            .apply_discovery(
                identity.public_key(),
                "10.42.0.2".parse().unwrap(),
                Some("192.0.2.10:51820".parse().unwrap()),
                true,
                Some("bob".into()),
            )
            .unwrap();
        assert_eq!(kind, ApplyKind::Added);
        assert_eq!(list.peers().len(), 1);
    }

    #[test]
    fn discovery_rejects_virtual_ip_mismatch_for_known_key() {
        let identity = Identity::generate();
        let pk = identity.public_key();
        let mut list = PeerList::new();
        list.add(Peer::new(pk, "10.42.0.2".parse().unwrap(), None, None).unwrap())
            .unwrap();
        let err = list
            .apply_discovery(pk, "10.42.0.3".parse().unwrap(), None, true, None)
            .unwrap_err();
        assert!(matches!(
            err,
            PeerError::VirtualIpMismatch {
                trusted,
                advertised
            } if trusted.to_string() == "10.42.0.2" && advertised.to_string() == "10.42.0.3"
        ));
        assert_eq!(list.peers()[0].virtual_ip.to_string(), "10.42.0.2");
    }
}
