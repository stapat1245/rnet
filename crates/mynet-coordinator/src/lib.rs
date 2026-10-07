//! In-memory (optionally persisted) membership registry.
//!
//! Stores public keys, overlay IPs, and UDP endpoints. Never stores private
//! keys. Never forwards VPN packets.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use mynet_core::parse_endpoint;
use mynet_identity::PublicKey;
use mynet_protocol::{
    decode_toml, encode_toml, read_frame, write_frame, AdvertisedPeer, ControlRequest,
    ControlResponse, KIND_ALLOCATE, KIND_DISCOVER, KIND_REGISTER,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct CoordinatorConfig {
    pub join_token: String,
    pub network: String,
    pub state_path: Option<PathBuf>,
}

impl CoordinatorConfig {
    pub fn from_env() -> Self {
        let join_token = std::env::var("MYNET_JOIN_TOKEN").unwrap_or_default();
        let network = std::env::var("MYNET_NETWORK").unwrap_or_else(|_| "mynet".to_string());
        let state_path = std::env::var("MYNET_STATE_PATH")
            .ok()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from);
        CoordinatorConfig {
            join_token,
            network,
            state_path,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredMember {
    #[serde(default)]
    token: String,
    public_key: String,
    virtual_ip: String,
    endpoint: String,
    last_seen_unix: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct StateFile {
    #[serde(default)]
    members: Vec<StoredMember>,
}

#[derive(Clone, Debug)]
struct Member {
    public_key: String,
    virtual_ip: Ipv4Addr,
    endpoint: SocketAddr,
    last_seen_unix: i64,
}

pub struct Registry {
    config: CoordinatorConfig,
    /// Isolated overlay rooms keyed by join/session token.
    rooms: HashMap<String, HashMap<String, Member>>,
}

impl Registry {
    pub fn new(config: CoordinatorConfig) -> Self {
        let mut reg = Registry {
            config,
            rooms: HashMap::new(),
        };
        if let Some(path) = reg.config.state_path.clone() {
            if let Err(e) = reg.load_from(&path) {
                tracing::warn!(error = %e, path = %path.display(), "could not load coordinator state");
            }
        }
        reg
    }

    fn room(&self, token: &str) -> Option<&HashMap<String, Member>> {
        self.rooms.get(token)
    }

    fn room_mut(&mut self, token: &str) -> &mut HashMap<String, Member> {
        self.rooms.entry(token.to_string()).or_default()
    }

    fn load_from(&mut self, path: &Path) -> Result<(), CoordError> {
        match fs::read_to_string(path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(CoordError::Io {
                path: path.to_path_buf(),
                source,
            }),
            Ok(text) => {
                let parsed: StateFile = toml::from_str(&text).map_err(|_| CoordError::Malformed)?;
                for rec in parsed.members {
                    if let Ok(member) = member_from_stored(&rec) {
                        let pk = member.public_key.clone();
                        self.room_mut(&rec.token).insert(pk, member);
                    }
                }
                Ok(())
            }
        }
    }

    fn persist(&self) -> Result<(), CoordError> {
        let Some(path) = self.config.state_path.as_ref() else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|source| CoordError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
        }
        let mut members = Vec::new();
        for (token, room) in &self.rooms {
            for m in room.values() {
                members.push(StoredMember {
                    token: token.clone(),
                    public_key: m.public_key.clone(),
                    virtual_ip: m.virtual_ip.to_string(),
                    endpoint: m.endpoint.to_string(),
                    last_seen_unix: m.last_seen_unix,
                });
            }
        }
        let file = StateFile { members };
        let serialized = toml::to_string_pretty(&file).map_err(|_| CoordError::Malformed)?;
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        let mut f = opts.open(path).map_err(|source| CoordError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        f.write_all(serialized.as_bytes()).map_err(|source| CoordError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(())
    }

    pub fn handle(
        &mut self,
        req: &ControlRequest,
        peer_addr: SocketAddr,
    ) -> ControlResponse {
        if let Err(msg) = self.check_token(&req.token) {
            return ControlResponse::error(msg);
        }
        match req.kind.as_str() {
            KIND_REGISTER => match self.register(req, peer_addr) {
                Ok(()) => ControlResponse::ok(self.advertise(&req.token)),
                Err(e) => ControlResponse::error(e.to_string()),
            },
            KIND_DISCOVER => ControlResponse::ok(self.advertise(&req.token)),
            KIND_ALLOCATE => match self.allocate_for(&req.token, &req.public_key) {
                Some(ip) => ControlResponse::allocated(ip.to_string()),
                None => ControlResponse::error("overlay address pool exhausted"),
            },
            other => ControlResponse::error(format!("unknown kind {other:?}")),
        }
    }

    fn check_token(&self, presented: &str) -> Result<(), String> {
        if self.config.join_token.is_empty() {
            return Ok(());
        }
        if presented == self.config.join_token {
            return Ok(());
        }
        if is_session_token(presented) {
            return Ok(());
        }
        Err("invalid join token".to_string())
    }

    fn register(&mut self, req: &ControlRequest, peer_addr: SocketAddr) -> Result<(), CoordError> {
        let public_key = PublicKey::from_base64(&req.public_key)
            .map_err(|_| CoordError::BadPublicKey)?;
        let pk = public_key.to_base64();
        let virtual_ip: Ipv4Addr = req
            .virtual_ip
            .parse()
            .map_err(|_| CoordError::BadVirtualIp)?;
        validate_overlay_ip(virtual_ip)?;
        if req.listen_port == 0 {
            return Err(CoordError::BadListenPort);
        }
        let endpoint = match &req.endpoint {
            Some(s) => parse_endpoint(s).map_err(|_| CoordError::BadEndpoint)?,
            None => ipv4_endpoint(peer_addr, req.listen_port)?,
        };
        let now = unix_now();
        let room_key = req.token.clone();

        {
            let room = self.room_mut(&room_key);
            if let Some(existing) = room.values().find(|m| m.virtual_ip == virtual_ip && m.public_key != pk)
            {
                return Err(CoordError::IpTaken(existing.virtual_ip));
            }
            if let Some(existing) = room.get(&pk) {
                if existing.virtual_ip != virtual_ip {
                    return Err(CoordError::KeyIpMismatch {
                        trusted: existing.virtual_ip,
                        advertised: virtual_ip,
                    });
                }
            }
            room.insert(
                pk.clone(),
                Member {
                    public_key: pk,
                    virtual_ip,
                    endpoint,
                    last_seen_unix: now,
                },
            );
        }
        self.persist()?;
        Ok(())
    }

    /// Same public key in the same room always gets the same overlay IP, so
    /// `rnet connect` after Ctrl-C does not allocate a new address and then
    /// fail registration.
    pub fn allocate_for(&self, token: &str, public_key: &str) -> Option<Ipv4Addr> {
        let pk = PublicKey::from_base64(public_key)
            .map(|k| k.to_base64())
            .unwrap_or_else(|_| public_key.to_string());
        if let Some(existing) = self.room(token).and_then(|r| r.get(&pk)) {
            return Some(existing.virtual_ip);
        }
        self.next_free_ip(token)
    }

    pub fn next_free_ip(&self, token: &str) -> Option<Ipv4Addr> {
        let room = self.room(token);
        for host in 1u8..=254 {
            let ip = Ipv4Addr::new(10, 42, 0, host);
            let taken = room.map(|r| r.values().any(|m| m.virtual_ip == ip)).unwrap_or(false);
            if !taken {
                return Some(ip);
            }
        }
        None
    }

    fn advertise(&self, token: &str) -> Vec<AdvertisedPeer> {
        let mut peers: Vec<AdvertisedPeer> = self
            .room(token)
            .map(|r| {
                r.values()
                    .map(|m| AdvertisedPeer {
                        public_key: m.public_key.clone(),
                        virtual_ip: m.virtual_ip.to_string(),
                        endpoint: Some(m.endpoint.to_string()),
                        last_seen_unix: m.last_seen_unix,
                    })
                    .collect()
            })
            .unwrap_or_default();
        peers.sort_by(|a, b| a.public_key.cmp(&b.public_key));
        peers
    }

    pub fn len(&self) -> usize {
        self.rooms.values().map(|r| r.len()).sum()
    }
}

fn is_session_token(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn member_from_stored(rec: &StoredMember) -> Result<Member, CoordError> {
    let public_key = PublicKey::from_base64(&rec.public_key).map_err(|_| CoordError::BadPublicKey)?;
    let virtual_ip: Ipv4Addr = rec.virtual_ip.parse().map_err(|_| CoordError::BadVirtualIp)?;
    validate_overlay_ip(virtual_ip)?;
    let endpoint = parse_endpoint(&rec.endpoint).map_err(|_| CoordError::BadEndpoint)?;
    Ok(Member {
        public_key: public_key.to_base64(),
        virtual_ip,
        endpoint,
        last_seen_unix: rec.last_seen_unix,
    })
}

fn validate_overlay_ip(ip: Ipv4Addr) -> Result<(), CoordError> {
    let o = ip.octets();
    if o[0] != 10 || o[1] != 42 || o[2] != 0 || o[3] == 0 || o[3] == 255 {
        return Err(CoordError::BadVirtualIp);
    }
    Ok(())
}

fn ipv4_endpoint(peer: SocketAddr, listen_port: u16) -> Result<SocketAddr, CoordError> {
    let ip = match peer.ip() {
        IpAddr::V4(v) => v,
        IpAddr::V6(v) => v
            .to_ipv4_mapped()
            .ok_or(CoordError::NeedDeclaredEndpoint)?,
    };
    Ok(SocketAddr::from((ip, listen_port)))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[derive(Debug, thiserror::Error)]
pub enum CoordError {
    #[error("public key is not a valid WireGuard/X25519 key")]
    BadPublicKey,
    #[error("virtual IP must be a usable address in 10.42.0.0/24")]
    BadVirtualIp,
    #[error("listen_port must not be 0")]
    BadListenPort,
    #[error("endpoint must be IPv4 host:port")]
    BadEndpoint,
    #[error("IPv6 TCP client must send endpoint= on register")]
    NeedDeclaredEndpoint,
    #[error("overlay IP {0} is already claimed by another public key")]
    IpTaken(Ipv4Addr),
    #[error("public key is already registered with overlay IP {trusted} (got {advertised})")]
    KeyIpMismatch {
        trusted: Ipv4Addr,
        advertised: Ipv4Addr,
    },
    #[error("malformed coordinator state")]
    Malformed,
    #[error("failed to access {}: {source}", .path.display())]
    Io {
        path: PathBuf,
        source: io::Error,
    },
}

pub fn serve(listener: TcpListener, config: CoordinatorConfig) -> io::Result<()> {
    let bind = listener.local_addr()?;
    if config.join_token.is_empty() {
        tracing::warn!("MYNET_JOIN_TOKEN is empty; anyone who can reach {bind} can register");
    }
    tracing::info!(
        %bind,
        network = %config.network,
        "coordinator listening (control plane only; VPN packets must not be sent here)"
    );
    let state = Arc::new(Mutex::new(Registry::new(config)));
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let state = Arc::clone(&state);
                thread::spawn(move || {
                    if let Err(e) = handle_client(stream, &state) {
                        tracing::debug!(error = %e, "session ended");
                    }
                });
            }
            Err(e) => tracing::warn!(error = %e, "accept failed"),
        }
    }
    Ok(())
}

fn handle_client(mut stream: TcpStream, state: &Mutex<Registry>) -> Result<(), mynet_protocol::ProtocolError> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;
    let peer = stream.peer_addr()?;
    let body = read_frame(&mut stream)?;
    let req: ControlRequest = decode_toml(&body)?;
    tracing::info!(
        peer = %peer,
        kind = %req.kind,
        public_key = %req.public_key,
        virtual_ip = %req.virtual_ip,
        "control request"
    );
    let response = {
        let mut reg = state.lock().unwrap_or_else(|e| e.into_inner());
        reg.handle(&req, peer)
    };
    write_frame(&mut stream, &encode_toml(&response)?)?;
    Ok(())
}

/// Serve `listener` in a background thread. The socket must already be bound.
pub fn spawn(listener: TcpListener, config: CoordinatorConfig) -> io::Result<SocketAddr> {
    let addr = listener.local_addr()?;
    thread::spawn(move || {
        if let Err(e) = serve(listener, config) {
            tracing::error!(error = %e, "coordinator stopped");
        }
    });
    Ok(addr)
}

/// Bind `127.0.0.1:0` and serve in a background thread. Used by tests.
pub fn spawn_for_test(config: CoordinatorConfig) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    spawn(listener, config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mynet_identity::Identity;
    use mynet_protocol::rpc;

    fn skip_if_denied<T>(res: io::Result<T>) -> Option<T> {
        match res {
            Ok(v) => Some(v),
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skip: TCP bind denied in this environment");
                None
            }
            Err(e) => panic!("{e}"),
        }
    }

    #[test]
    fn two_peers_register_and_discover() {
        let Some(addr) = skip_if_denied(spawn_for_test(CoordinatorConfig {
            join_token: "secret".into(),
            network: "lab".into(),
            state_path: None,
        })) else {
            return;
        };
        let coord = addr.to_string();
        let alice = Identity::generate();
        let bob = Identity::generate();
        let alice_pk = alice.public_key().to_base64();
        let bob_pk = bob.public_key().to_base64();

        let a = rpc(
            &coord,
            &ControlRequest::register(
                "secret",
                &alice_pk,
                "10.42.0.1",
                51820,
                Some("192.0.2.10:51820".into()),
            ),
        )
        .unwrap();
        assert!(a.is_ok());

        let b = rpc(
            &coord,
            &ControlRequest::register(
                "secret",
                &bob_pk,
                "10.42.0.2",
                51820,
                Some("198.51.100.20:51820".into()),
            ),
        )
        .unwrap();
        assert_eq!(b.peers.len(), 2);
        assert!(b.peers.iter().any(|p| p.public_key == alice_pk));
        assert!(b.peers.iter().any(|p| p.public_key == bob_pk));
        let alice_ep = b
            .peers
            .iter()
            .find(|p| p.public_key == alice_pk)
            .unwrap()
            .endpoint
            .as_deref();
        assert_eq!(alice_ep, Some("192.0.2.10:51820"));

        let listed = rpc(&coord, &ControlRequest::discover("secret", &alice_pk)).unwrap();
        assert_eq!(listed.peers.len(), 2);
        assert!(listed
            .peers
            .iter()
            .all(|p| !format!("{p:?}").to_lowercase().contains("private")));
    }

    #[test]
    fn allocate_returns_first_free_overlay_ip() {
        let mut reg = Registry::new(CoordinatorConfig {
            join_token: String::new(),
            network: "lab".into(),
            state_path: None,
        });
        let alice = Identity::generate();
        let resp = reg.handle(
            &ControlRequest::allocate("", alice.public_key().to_base64()),
            "127.0.0.1:9".parse().unwrap(),
        );
        assert!(resp.is_ok());
        assert_eq!(resp.assigned_ip.as_deref(), Some("10.42.0.1"));
        let req = ControlRequest::register(
            "",
            alice.public_key().to_base64(),
            "10.42.0.1",
            51820,
            Some("192.0.2.10:51820".into()),
        );
        assert!(reg.handle(&req, "127.0.0.1:9".parse().unwrap()).is_ok());
        let bob = Identity::generate();
        let resp = reg.handle(
            &ControlRequest::allocate("", bob.public_key().to_base64()),
            "127.0.0.1:9".parse().unwrap(),
        );
        assert_eq!(resp.assigned_ip.as_deref(), Some("10.42.0.2"));
    }

    #[test]
    fn allocate_reuses_ip_when_the_same_key_reconnects() {
        let mut reg = Registry::new(CoordinatorConfig {
            join_token: String::new(),
            network: "lab".into(),
            state_path: None,
        });
        let alice = Identity::generate();
        let bob = Identity::generate();
        let alice_pk = alice.public_key().to_base64();
        let bob_pk = bob.public_key().to_base64();
        let a = ControlRequest::register(
            "",
            &alice_pk,
            "10.42.0.1",
            51820,
            Some("192.0.2.10:51820".into()),
        );
        let b = ControlRequest::register(
            "",
            &bob_pk,
            "10.42.0.2",
            51820,
            Some("198.51.100.20:51820".into()),
        );
        assert!(reg.handle(&a, "127.0.0.1:9".parse().unwrap()).is_ok());
        assert!(reg.handle(&b, "127.0.0.1:9".parse().unwrap()).is_ok());

        let again = reg.handle(
            &ControlRequest::allocate("", &bob_pk),
            "127.0.0.1:9".parse().unwrap(),
        );
        assert!(again.is_ok(), "{again:?}");
        assert_eq!(again.assigned_ip.as_deref(), Some("10.42.0.2"));

        let rejoin = ControlRequest::register(
            "",
            &bob_pk,
            "10.42.0.2",
            51820,
            Some("198.51.100.20:51820".into()),
        );
        let resp = reg.handle(&rejoin, "127.0.0.1:9".parse().unwrap());
        assert!(resp.is_ok(), "{resp:?}");
        let bob_rec = resp.peers.iter().find(|p| p.public_key == bob_pk).unwrap();
        assert_eq!(bob_rec.virtual_ip, "10.42.0.2");
    }

    #[test]
    fn bad_token_rejected() {
        let Some(addr) = skip_if_denied(spawn_for_test(CoordinatorConfig {
            join_token: "secret".into(),
            network: "lab".into(),
            state_path: None,
        })) else {
            return;
        };
        let alice = Identity::generate();
        let err = rpc(
            &addr.to_string(),
            &ControlRequest::register(
                "nope",
                alice.public_key().to_base64(),
                "10.42.0.1",
                51820,
                Some("192.0.2.10:51820".into()),
            ),
        )
        .unwrap_err();
        match err {
            mynet_protocol::ProtocolError::Remote(msg) => {
                assert!(msg.contains("token"), "{msg}");
            }
            other => panic!("{other}"),
        }
    }

    #[test]
    fn same_key_cannot_change_overlay_ip() {
        let Some(addr) = skip_if_denied(spawn_for_test(CoordinatorConfig {
            join_token: String::new(),
            network: "lab".into(),
            state_path: None,
        })) else {
            return;
        };
        let coord = addr.to_string();
        let alice = Identity::generate();
        let pk = alice.public_key().to_base64();
        rpc(
            &coord,
            &ControlRequest::register(
                "",
                &pk,
                "10.42.0.1",
                51820,
                Some("192.0.2.10:51820".into()),
            ),
        )
        .unwrap();
        let err = rpc(
            &coord,
            &ControlRequest::register(
                "",
                &pk,
                "10.42.0.9",
                51820,
                Some("192.0.2.10:51820".into()),
            ),
        )
        .unwrap_err();
        match err {
            mynet_protocol::ProtocolError::Remote(msg) => {
                assert!(msg.contains("10.42.0.1"), "{msg}");
            }
            other => panic!("{other}"),
        }
    }

    #[test]
    fn endpoint_update_keeps_identity() {
        let Some(addr) = skip_if_denied(spawn_for_test(CoordinatorConfig {
            join_token: String::new(),
            network: "lab".into(),
            state_path: None,
        })) else {
            return;
        };
        let coord = addr.to_string();
        let alice = Identity::generate();
        let pk = alice.public_key().to_base64();
        rpc(
            &coord,
            &ControlRequest::register(
                "",
                &pk,
                "10.42.0.1",
                51820,
                Some("192.0.2.10:51820".into()),
            ),
        )
        .unwrap();
        let updated = rpc(
            &coord,
            &ControlRequest::register(
                "",
                &pk,
                "10.42.0.1",
                51821,
                Some("203.0.113.50:51821".into()),
            ),
        )
        .unwrap();
        let rec = updated.peers.iter().find(|p| p.public_key == pk).unwrap();
        assert_eq!(rec.virtual_ip, "10.42.0.1");
        assert_eq!(rec.endpoint.as_deref(), Some("203.0.113.50:51821"));
    }

    #[test]
    fn persist_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.toml");
        let cfg = CoordinatorConfig {
            join_token: "t".into(),
            network: "lab".into(),
            state_path: Some(path.clone()),
        };
        let mut reg = Registry::new(cfg.clone());
        let alice = Identity::generate();
        let req = ControlRequest::register(
            "t",
            alice.public_key().to_base64(),
            "10.42.0.1",
            51820,
            Some("192.0.2.10:51820".into()),
        );
        assert!(reg.handle(&req, "127.0.0.1:9".parse().unwrap()).is_ok());
        drop(reg);
        let loaded = Registry::new(cfg);
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn session_rooms_are_isolated() {
        let mut reg = Registry::new(CoordinatorConfig {
            join_token: "master".into(),
            network: "lab".into(),
            state_path: None,
        });
        let alice = Identity::generate();
        let bob = Identity::generate();
        let room_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let room_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let a = ControlRequest::register(
            room_a,
            alice.public_key().to_base64(),
            "10.42.0.1",
            51820,
            Some("192.0.2.10:51820".into()),
        );
        let b = ControlRequest::register(
            room_b,
            bob.public_key().to_base64(),
            "10.42.0.1",
            51820,
            Some("198.51.100.20:51820".into()),
        );
        let ra = reg.handle(&a, "127.0.0.1:9".parse().unwrap());
        let rb = reg.handle(&b, "127.0.0.1:9".parse().unwrap());
        assert!(ra.is_ok(), "{ra:?}");
        assert!(rb.is_ok(), "{rb:?}");
        assert_eq!(ra.peers.len(), 1);
        assert_eq!(rb.peers.len(), 1);
        assert_eq!(ra.peers[0].public_key, alice.public_key().to_base64());
        assert_eq!(rb.peers[0].public_key, bob.public_key().to_base64());
    }

    #[test]
    fn no_forward_kind() {
        let mut reg = Registry::new(CoordinatorConfig {
            join_token: String::new(),
            network: "lab".into(),
            state_path: None,
        });
        let req = ControlRequest {
            kind: "forward".into(),
            token: String::new(),
            public_key: Identity::generate().public_key().to_base64(),
            virtual_ip: "10.42.0.1".into(),
            listen_port: 51820,
            endpoint: None,
        };
        let resp = reg.handle(&req, "127.0.0.1:9".parse().unwrap());
        assert!(!resp.is_ok());
        assert!(resp.message.unwrap().contains("unknown kind"));
    }
}
