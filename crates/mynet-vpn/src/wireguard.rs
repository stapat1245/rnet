//! Kernel WireGuard configuration via `ip` and `wg`.
//!
//! Private keys are written to a mode-0600 temp file, passed to `wg set`,
//! then deleted. They are never logged.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use zeroize::Zeroize;

use crate::tun::{find_ip, ip, TunError};

#[derive(Clone, Debug)]
pub struct WgPeer {
    pub public_key_base64: String,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ip: Ipv4Addr,
}

#[derive(Debug, thiserror::Error)]
pub enum WgError {
    #[error("{0}")]
    Tun(#[from] TunError),
    #[error("`wg` command not found")]
    WgMissing,
    #[error("wg {args:?} failed: {stderr}")]
    WgFailed { args: Vec<String>, stderr: String },
    #[error("wireguard key file {path}: {source}", path = .path.display())]
    KeyFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Create/configure a kernel WireGuard interface.
///
/// `private_key` is 32 raw X25519 bytes. It is not logged.
pub fn apply_wireguard(
    iface: &str,
    private_key: &[u8; 32],
    listen_port: u16,
    addr: Ipv4Addr,
    prefix: u8,
    peers: &[WgPeer],
) -> Result<(), WgError> {
    ensure_wg()?;
    let _ = ip(&["link", "del", "dev", iface]);
    ip(&["link", "add", "dev", iface, "type", "wireguard"])?;

    let key_path = write_private_key(private_key)?;
    let mut args: Vec<String> = vec![
        "set".into(),
        iface.into(),
        "listen-port".into(),
        listen_port.to_string(),
        "private-key".into(),
        key_path.display().to_string(),
    ];
    for peer in peers {
        args.push("peer".into());
        args.push(peer.public_key_base64.clone());
        args.push("allowed-ips".into());
        args.push(format!("{}/32", peer.allowed_ip));
        if let Some(ep) = peer.endpoint {
            args.push("endpoint".into());
            args.push(ep.to_string());
            args.push("persistent-keepalive".into());
            args.push("25".into());
        }
    }
    let result = wg(args.iter().map(|s| s.as_str()).collect::<Vec<_>>().as_slice());
    let _ = fs::remove_file(&key_path);
    result?;

    let cidr = format!("{addr}/{prefix}");
    ip(&["addr", "replace", &cidr, "dev", iface])?;
    ip(&["link", "set", "dev", iface, "up"])?;
    tracing::info!(
        interface = %iface,
        listen_port,
        peers = peers.len(),
        "kernel WireGuard configured"
    );
    Ok(())
}

pub fn teardown_wireguard(iface: &str) -> Result<(), WgError> {
    match ip(&["link", "del", "dev", iface]) {
        Ok(()) => Ok(()),
        Err(TunError::IpFailed { stderr, .. }) if stderr.contains("Cannot find device") => Ok(()),
        Err(e) => Err(WgError::Tun(e)),
    }
}

/// `wg set` argument vector without running it. Used in unit tests.
pub fn wg_set_args(
    iface: &str,
    listen_port: u16,
    key_path: &Path,
    peers: &[WgPeer],
) -> Vec<String> {
    let mut args = vec![
        "set".to_string(),
        iface.to_string(),
        "listen-port".to_string(),
        listen_port.to_string(),
        "private-key".to_string(),
        key_path.display().to_string(),
    ];
    for peer in peers {
        args.push("peer".into());
        args.push(peer.public_key_base64.clone());
        args.push("allowed-ips".into());
        args.push(format!("{}/32", peer.allowed_ip));
        if let Some(ep) = peer.endpoint {
            args.push("endpoint".into());
            args.push(ep.to_string());
            args.push("persistent-keepalive".into());
            args.push("25".into());
        }
    }
    args
}

fn write_private_key(key: &[u8; 32]) -> Result<PathBuf, WgError> {
    let mut encoded = BASE64.encode(key);
    let path = std::env::temp_dir().join(format!("mynet-wg-{}.key", std::process::id()));
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true).mode(0o600);
    let write_res = (|| {
        let mut f = opts.open(&path)?;
        f.write_all(encoded.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()
    })();
    encoded.zeroize();
    write_res.map_err(|source| WgError::KeyFile {
        path: path.clone(),
        source,
    })?;
    Ok(path)
}

fn ensure_wg() -> Result<(), WgError> {
    find_wg().map(|_| ())
}

fn find_wg() -> Result<PathBuf, WgError> {
    for candidate in ["/usr/bin/wg", "/usr/sbin/wg", "wg"] {
        if candidate.starts_with('/') {
            if Path::new(candidate).exists() {
                return Ok(Path::new(candidate).to_path_buf());
            }
        } else if Command::new(candidate).arg("--version").output().is_ok() {
            return Ok(Path::new(candidate).to_path_buf());
        }
    }
    Err(WgError::WgMissing)
}

fn wg(args: &[&str]) -> Result<(), WgError> {
    let bin = find_wg()?;
    let out = Command::new(&bin)
        .args(args)
        .output()
        .map_err(|e| WgError::WgFailed {
            args: args.iter().map(|s| (*s).to_string()).collect(),
            stderr: e.to_string(),
        })?;
    if out.status.success() {
        return Ok(());
    }
    Err(WgError::WgFailed {
        args: args.iter().map(|s| (*s).to_string()).collect(),
        stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
    })
}

#[allow(dead_code)]
fn _ip_bin() -> Result<PathBuf, TunError> {
    find_ip()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn wg_args_include_peer_and_keepalive() {
        let peer = WgPeer {
            public_key_base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            endpoint: Some("192.0.2.10:51820".parse().unwrap()),
            allowed_ip: Ipv4Addr::new(10, 42, 0, 2),
        };
        let args = wg_set_args("mynet0", 51820, Path::new("/tmp/k"), &[peer]);
        assert!(args.contains(&"peer".to_string()));
        assert!(args.contains(&"10.42.0.2/32".to_string()));
        assert!(args.contains(&"192.0.2.10:51820".to_string()));
        assert!(args.contains(&"25".to_string()));
        assert!(args.contains(&"private-key".to_string()));
        assert!(args.contains(&"/tmp/k".to_string()));
    }
}
