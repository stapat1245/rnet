//! Local overlay settings for this node.
//!
//! Virtual IP is an address on the overlay, not identity. Listen port and
//! interface name are transport/virtual-network configuration.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{DEFAULT_INTERFACE, DEFAULT_LISTEN_PORT};

const SCHEMA_VERSION: u32 = 1;
const FILE_MODE: u32 = 0o600;

/// This node's overlay address and data-plane bind settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalConfig {
    pub virtual_ip: Ipv4Addr,
    pub listen_port: u16,
    pub interface: String,
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
        Self::new(ip, parsed.listen_port, parsed.interface)
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
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct FileOnDisk {
    schema_version: u32,
    virtual_ip: String,
    listen_port: u16,
    interface: String,
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
}

fn validate_overlay_ip(ip: Ipv4Addr) -> Result<(), LocalError> {
    let o = ip.octets();
    if o[0] != 10 || o[1] != 42 || o[2] != 0 || o[3] == 0 || o[3] == 255 {
        return Err(LocalError::InvalidVirtualIp(ip));
    }
    Ok(())
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
}
