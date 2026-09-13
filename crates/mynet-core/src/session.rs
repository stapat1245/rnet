//! Per-peer connection state machine (Phase 11).
//!
//! Live state lives in `session.toml` while `mynet connect` runs. It is not
//! identity and is not persisted in `peers.toml`. Relay is a first-class
//! state; the data-plane fallback is Phase 13.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::peer::PeerState;

const SCHEMA_VERSION: u32 = 1;
const FILE_MODE: u32 = 0o600;

/// Seconds to wait in `Connecting` for a WireGuard handshake before failing
/// over to relay (if configured) or `Failed`.
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 15;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionEvent {
    Start,
    EndpointKnown,
    NoEndpoint,
    HandshakeOk,
    HandshakeTimeout,
    RelayReady,
    RelayUp,
    RelayFail,
    Disconnect,
    Retry,
}

impl SessionEvent {
    pub fn as_str(self) -> &'static str {
        match self {
            SessionEvent::Start => "start",
            SessionEvent::EndpointKnown => "endpoint_known",
            SessionEvent::NoEndpoint => "no_endpoint",
            SessionEvent::HandshakeOk => "handshake_ok",
            SessionEvent::HandshakeTimeout => "handshake_timeout",
            SessionEvent::RelayReady => "relay_ready",
            SessionEvent::RelayUp => "relay_up",
            SessionEvent::RelayFail => "relay_fail",
            SessionEvent::Disconnect => "disconnect",
            SessionEvent::Retry => "retry",
        }
    }
}

impl std::fmt::Display for SessionEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SessionError {
    #[error("invalid session transition {from} --{event}-->")]
    Invalid {
        from: &'static str,
        event: &'static str,
    },
}

impl PeerState {
    /// Apply one event. Invalid combinations return `Err` and leave state
    /// unchanged at the call site (this method is a pure function).
    pub fn transition(self, event: SessionEvent) -> Result<PeerState, SessionError> {
        use PeerState::*;
        use SessionEvent::*;
        let next = match (self, event) {
            (Disconnected, Start) => Discovering,
            (Disconnected, Disconnect) => Disconnected,
            (Discovering, EndpointKnown) => Connecting,
            (Discovering, NoEndpoint) => Failed,
            (Discovering, RelayReady) => Relaying,
            (Discovering, Disconnect) => Disconnected,
            (Connecting, HandshakeOk) => Direct,
            (Connecting, HandshakeTimeout) => Failed,
            (Connecting, RelayReady) => Relaying,
            (Connecting, Disconnect) => Disconnected,
            (Direct, HandshakeOk) => Direct,
            (Direct, EndpointKnown) => Connecting,
            (Direct, HandshakeTimeout) => Failed,
            (Direct, RelayReady) => Relaying,
            (Direct, Disconnect) => Disconnected,
            (Relaying, HandshakeOk) => Relaying,
            (Relaying, RelayUp) => Relaying,
            (Relaying, RelayFail) => Failed,
            (Relaying, EndpointKnown) => Connecting,
            (Relaying, Disconnect) => Disconnected,
            (Failed, Retry) => Discovering,
            (Failed, Disconnect) => Disconnected,
            (Failed, RelayReady) => Relaying,
            _ => {
                return Err(SessionError::Invalid {
                    from: self.as_str(),
                    event: event.as_str(),
                });
            }
        };
        Ok(next)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRow {
    pub public_key: String,
    pub state: PeerState,
    pub endpoint: Option<SocketAddr>,
    pub last_event: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionTable {
    rows: HashMap<String, SessionRow>,
}

impl SessionTable {
    pub fn new() -> Self {
        SessionTable {
            rows: HashMap::new(),
        }
    }

    pub fn get(&self, public_key: &str) -> Option<&SessionRow> {
        self.rows.get(public_key)
    }

    pub fn rows(&self) -> impl Iterator<Item = &SessionRow> {
        self.rows.values()
    }

    pub fn apply(
        &mut self,
        public_key: &str,
        event: SessionEvent,
        endpoint: Option<SocketAddr>,
    ) -> Result<PeerState, SessionError> {
        let current = self
            .rows
            .get(public_key)
            .map(|r| r.state)
            .unwrap_or(PeerState::Disconnected);
        let next = current.transition(event)?;
        tracing::info!(
            peer = %public_key,
            from = %current,
            to = %next,
            event = %event,
            "session transition"
        );
        self.rows.insert(
            public_key.to_string(),
            SessionRow {
                public_key: public_key.to_string(),
                state: next,
                endpoint: endpoint.or_else(|| {
                    self.rows
                        .get(public_key)
                        .and_then(|r| r.endpoint)
                }),
                last_event: event.as_str().to_string(),
            },
        );
        Ok(next)
    }

    pub fn load_from(path: &Path) -> Result<Self, SessionIoError> {
        match fs::read_to_string(path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(SessionTable::new()),
            Err(source) => {
                return Err(SessionIoError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
            Ok(text) => {
                let parsed: FileOnDisk = toml::from_str(&text).map_err(|_| SessionIoError::Malformed {
                    path: path.to_path_buf(),
                })?;
                let mut table = SessionTable::new();
                for rec in parsed.peers {
                    let Some(state) = PeerState::from_str(&rec.state) else {
                        continue;
                    };
                    let endpoint = rec
                        .endpoint
                        .as_deref()
                        .and_then(|s| s.parse().ok());
                    table.rows.insert(
                        rec.public_key.clone(),
                        SessionRow {
                            public_key: rec.public_key,
                            state,
                            endpoint,
                            last_event: rec.last_event.unwrap_or_default(),
                        },
                    );
                }
                Ok(table)
            }
        }
    }

    pub fn save_to(&self, path: &Path) -> Result<(), SessionIoError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|source| SessionIoError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
        }
        let mut peers: Vec<FileRow> = self
            .rows
            .values()
            .map(|r| FileRow {
                public_key: r.public_key.clone(),
                state: r.state.as_str().to_string(),
                endpoint: r.endpoint.map(|e| e.to_string()),
                last_event: Some(r.last_event.clone()),
            })
            .collect();
        peers.sort_by(|a, b| a.public_key.cmp(&b.public_key));
        let file = FileOnDisk {
            schema_version: SCHEMA_VERSION,
            peers,
        };
        let serialized = toml::to_string_pretty(&file).map_err(|_| SessionIoError::Malformed {
            path: path.to_path_buf(),
        })?;
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(FILE_MODE);
        let mut f = opts.open(path).map_err(|source| SessionIoError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        f.write_all(serialized.as_bytes()).map_err(|source| SessionIoError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let mut perms = fs::metadata(path)
            .map_err(|source| SessionIoError::Io {
                path: path.to_path_buf(),
                source,
            })?
            .permissions();
        perms.set_mode(FILE_MODE);
        fs::set_permissions(path, perms).map_err(|source| SessionIoError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(())
    }

    pub fn remove_file(path: &Path) -> Result<(), SessionIoError> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(SessionIoError::Io {
                path: path.to_path_buf(),
                source,
            }),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SessionIoError {
    #[error("session file {} is malformed", .path.display())]
    Malformed { path: PathBuf },
    #[error("failed to access {}: {source}", .path.display())]
    Io {
        path: PathBuf,
        source: io::Error,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct FileOnDisk {
    schema_version: u32,
    #[serde(default)]
    peers: Vec<FileRow>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileRow {
    public_key: String,
    state: String,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    last_event: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use PeerState::*;
    use SessionEvent::*;

    #[test]
    fn transition_table() {
        let cases = [
            (Disconnected, Start, Ok(Discovering)),
            (Discovering, EndpointKnown, Ok(Connecting)),
            (Discovering, NoEndpoint, Ok(Failed)),
            (Discovering, RelayReady, Ok(Relaying)),
            (Connecting, HandshakeOk, Ok(Direct)),
            (Connecting, HandshakeTimeout, Ok(Failed)),
            (Connecting, RelayReady, Ok(Relaying)),
            (Direct, HandshakeOk, Ok(Direct)),
            (Direct, EndpointKnown, Ok(Connecting)),
            (Direct, RelayReady, Ok(Relaying)),
            (Relaying, HandshakeOk, Ok(Relaying)),
            (Relaying, RelayFail, Ok(Failed)),
            (Relaying, EndpointKnown, Ok(Connecting)),
            (Failed, Retry, Ok(Discovering)),
            (Direct, Disconnect, Ok(Disconnected)),
        ];
        for (from, event, expect) in cases {
            assert_eq!(from.transition(event), expect, "{from} {event}");
        }
    }

    #[test]
    fn invalid_transition_rejected() {
        let err = PeerState::Disconnected
            .transition(SessionEvent::HandshakeOk)
            .unwrap_err();
        assert!(matches!(err, SessionError::Invalid { .. }));
    }

    #[test]
    fn apply_traces_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.toml");
        let mut table = SessionTable::new();
        table.apply("pkA", Start, None).unwrap();
        table
            .apply("pkA", EndpointKnown, Some("192.0.2.10:51820".parse().unwrap()))
            .unwrap();
        table.apply("pkA", HandshakeOk, None).unwrap();
        assert_eq!(table.get("pkA").unwrap().state, Direct);
        table.save_to(&path).unwrap();
        let loaded = SessionTable::load_from(&path).unwrap();
        assert_eq!(loaded.get("pkA").unwrap().state, Direct);
        SessionTable::remove_file(&path).unwrap();
        assert!(SessionTable::load_from(&path).unwrap().get("pkA").is_none());
    }
}
