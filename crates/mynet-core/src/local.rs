//! Local overlay settings for this node.
//!
//! Virtual IP is an address on the overlay, not identity. Listen port and
//! interface name are transport/virtual-network configuration.

use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{DEFAULT_INTERFACE, DEFAULT_LISTEN_PORT};

const SCHEMA_VERSION: u32 = 1;
const FILE_MODE: u32 = 0o600;

/// This node's overlay address, data-plane bind, and optional coordinator.
///
/// `join_token` is a membership secret. It is stored mode `0600` and redacted
/// from `Debug`. It is never a WireGuard key and never sent on the data plane.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalConfig {
    pub virtual_ip: Ipv4Addr,
    pub listen_port: u16,
    pub interface: String,
    pub coordinator: Option<String>,
    pub network: Option<String>,
    pub join_token: Option<String>,
    pub relay: Option<String>,
}

impl fmt::Debug for LocalConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalConfig")
            .field("virtual_ip", &self.virtual_ip)
            .field("listen_port", &self.listen_port)
            .field("interface", &self.interface)
            .field("coordinator", &self.coordinator)
            .field("network", &self.network)
            .field("join_token", &self.join_token.as_ref().map(|_| "[redacted]"))
            .field("relay", &self.relay)
            .finish()
    }
}

impl LocalConfig {
    pub fn new(virtual_ip: Ipv4Addr, listen_port: u16, interface: String) -> Result<Self, LocalError> {
        validate_overlay_ip(virtual_ip)?;
        if listen_port == 0 {
            return Err(LocalError::InvalidListenPort);
        }
        validate_iface(&interface)?;
        Ok(LocalConfig {
            virtual_ip,
            listen_port,
            interface,
            coordinator: None,
            network: None,
            join_token: None,
            relay: None,
        })
    }

    pub fn load_from(path: &Path) -> Result<Self, LocalError> {
        let text = fs::read_to_string(path).map_err(|source| {
            if source.kind() == io::ErrorKind::NotFound {
                LocalError::NotFound {
                    path: path.to_path_buf(),
                }
            } else {
                LocalError::Io {
                    path: path.to_path_buf(),
                    source,
                }
            }
        })?;
        let parsed: FileOnDisk = toml::from_str(&text).map_err(|_| LocalError::Malformed {
            path: path.to_path_buf(),
            reason: "file is not valid local TOML".to_string(),
        })?;
        if parsed.schema_version != SCHEMA_VERSION {
            return Err(LocalError::Malformed {
                path: path.to_path_buf(),
                reason: format!(
                    "unsupported schema_version {} (expected {SCHEMA_VERSION})",
                    parsed.schema_version
                ),
            });
        }
        let ip: Ipv4Addr = parsed.virtual_ip.parse().map_err(|_| LocalError::Malformed {
            path: path.to_path_buf(),
            reason: format!("invalid virtual_ip {}", parsed.virtual_ip),
        })?;
        let mut cfg = Self::new(ip, parsed.listen_port, parsed.interface)?;
        cfg.coordinator = normalize_opt(parsed.coordinator);
        cfg.network = normalize_opt(parsed.network);
        cfg.join_token = normalize_opt(parsed.join_token);
        cfg.relay = normalize_opt(parsed.relay);
        if let Some(ref coord) = cfg.coordinator {
            validate_host_port(coord)?;
        }
        if let Some(ref relay) = cfg.relay {
            validate_host_port(relay)?;
        }
        Ok(cfg)
    }

    pub fn save_to(&self, path: &Path) -> Result<(), LocalError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|source| LocalError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
        }
        let file = FileOnDisk {
            schema_version: SCHEMA_VERSION,
            virtual_ip: self.virtual_ip.to_string(),
            listen_port: self.listen_port,
            interface: self.interface.clone(),
            coordinator: self.coordinator.clone(),
            network: self.network.clone(),
            join_token: self.join_token.clone(),
            relay: self.relay.clone(),
        };
        let serialized = toml::to_string_pretty(&file).map_err(|source| LocalError::Serialize {
            path: path.to_path_buf(),
            source,
        })?;
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(FILE_MODE);
        let mut f = opts.open(path).map_err(|source| LocalError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        f.write_all(serialized.as_bytes()).map_err(|source| LocalError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let mut perms = fs::metadata(path)
            .map_err(|source| LocalError::Io {
                path: path.to_path_buf(),
                source,
            })?
            .permissions();
        perms.set_mode(FILE_MODE);
        fs::set_permissions(path, perms).map_err(|source| LocalError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(())
    }
}

impl Default for LocalConfig {
    fn default() -> Self {
        LocalConfig {
            virtual_ip: Ipv4Addr::new(10, 42, 0, 1),
            listen_port: DEFAULT_LISTEN_PORT,
            interface: DEFAULT_INTERFACE.to_string(),
            coordinator: None,
            network: None,
            join_token: None,
            relay: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct FileOnDisk {
    schema_version: u32,
    virtual_ip: String,
    listen_port: u16,
    interface: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    coordinator: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    network: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    join_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    relay: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum LocalError {
    #[error("local config not found at {}; pass --ip or run connect once", .path.display())]
    NotFound { path: PathBuf },
    #[error("local config {} is malformed: {reason}", .path.display())]
    Malformed { path: PathBuf, reason: String },
    #[error("failed to serialize local config for {}: {source}", .path.display())]
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
    #[error("virtual IP {0} must be a usable address in 10.42.0.0/24")]
    InvalidVirtualIp(Ipv4Addr),
    #[error("listen port must not be 0")]
    InvalidListenPort,
    #[error("interface name {0:?} is invalid; use 1-15 ASCII [A-Za-z0-9_-]")]
    InvalidInterface(String),
    #[error("coordinator must be host:port (got {0:?})")]
    InvalidCoordinator(String),
}

fn validate_overlay_ip(ip: Ipv4Addr) -> Result<(), LocalError> {
    let o = ip.octets();
    if o[0] != 10 || o[1] != 42 || o[2] != 0 || o[3] == 0 || o[3] == 255 {
        return Err(LocalError::InvalidVirtualIp(ip));
    }
    Ok(())
}

fn normalize_opt(value: Option<String>) -> Option<String> {
    value.and_then(|s| {
        let t = s.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    })
}

/// Split `host:port` on the last colon. Hostnames are allowed; IPv6 is not.
pub fn split_host_port(s: &str) -> Result<(&str, u16), LocalError> {
    let s = s.trim();
    let idx = s.rfind(':').ok_or_else(|| LocalError::InvalidCoordinator(s.to_string()))?;
    let host = &s[..idx];
    let port: u16 = s[idx + 1..]
        .parse()
        .map_err(|_| LocalError::InvalidCoordinator(s.to_string()))?;
    if host.is_empty() || port == 0 {
        return Err(LocalError::InvalidCoordinator(s.to_string()));
    }
    if host.starts_with('[') {
        return Err(LocalError::InvalidCoordinator(s.to_string()));
    }
    Ok((host, port))
}

fn validate_host_port(s: &str) -> Result<(), LocalError> {
    split_host_port(s).map(|_| ())
}

pub(crate) fn validate_iface(name: &str) -> Result<(), LocalError> {
    if name.is_empty()
        || name.len() > 15
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(LocalError::InvalidInterface(name.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("local.toml");
        let cfg = LocalConfig::new(
            "10.42.0.1".parse().unwrap(),
            51820,
            "mynet0".into(),
        )
        .unwrap();
        cfg.save_to(&path).unwrap();
        let loaded = LocalConfig::load_from(&path).unwrap();
        assert_eq!(cfg, loaded);
    }

    #[test]
    fn rejects_off_overlay() {
        assert!(LocalConfig::new("8.8.8.8".parse().unwrap(), 51820, "mynet0".into()).is_err());
    }

    #[test]
    fn coordinator_fields_round_trip_and_debug_redacts_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("local.toml");
        let mut cfg = LocalConfig::new(
            "10.42.0.1".parse().unwrap(),
            51820,
            "mynet0".into(),
        )
        .unwrap();
        cfg.coordinator = Some("203.0.113.10:9993".into());
        cfg.network = Some("office".into());
        cfg.join_token = Some("super-secret-token".into());
        cfg.save_to(&path).unwrap();
        let loaded = LocalConfig::load_from(&path).unwrap();
        assert_eq!(loaded.coordinator.as_deref(), Some("203.0.113.10:9993"));
        assert_eq!(loaded.join_token.as_deref(), Some("super-secret-token"));
        let debug = format!("{loaded:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("super-secret-token"));
    }

    #[test]
    fn old_local_toml_without_coordinator_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("local.toml");
        std::fs::write(
            &path,
            "schema_version = 1\nvirtual_ip = \"10.42.0.2\"\nlisten_port = 51820\ninterface = \"mynet0\"\n",
        )
        .unwrap();
        let loaded = LocalConfig::load_from(&path).unwrap();
        assert_eq!(loaded.virtual_ip, Ipv4Addr::new(10, 42, 0, 2));
        assert!(loaded.coordinator.is_none());
        assert!(loaded.join_token.is_none());
    }

    #[test]
    fn split_host_port_ipv4() {
        let (host, port) = split_host_port("203.0.113.9:8443").unwrap();
        assert_eq!(host, "203.0.113.9");
        assert_eq!(port, 8443);
    }
}
