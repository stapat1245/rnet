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
use mynet_core::WG_PERSISTENT_KEEPALIVE_SECS;

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
    #[error(
        "`wg` command not found; install wireguard-tools (e.g. `sudo apt-get install -y wireguard wireguard-tools`)"
    )]
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
            args.push(WG_PERSISTENT_KEEPALIVE_SECS.to_string());
        }
    }
    let result = wg(args.iter().map(|s| s.as_str()).collect::<Vec<_>>().as_slice());
    let _ = fs::remove_file(&key_path);
    result?;

    let cidr = format!("{addr}/{prefix}");
    ip(&["addr", "replace", &cidr, "dev", iface])?;
    ip(&["link", "set", "dev", iface, "up"])?;
    crate::tun::install_overlay_route(iface)?;
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
            args.push(WG_PERSISTENT_KEEPALIVE_SECS.to_string());
        }
    }
    args
}

/// Add or update one WireGuard peer without rewriting the private key.
pub fn upsert_wg_peer(iface: &str, peer: &WgPeer) -> Result<(), WgError> {
    ensure_wg()?;
    let args = upsert_wg_peer_args(iface, peer);
    wg(&args.iter().map(|s| s.as_str()).collect::<Vec<_>>())
}

pub fn upsert_wg_peer_args(iface: &str, peer: &WgPeer) -> Vec<String> {
    let mut args = vec![
        "set".into(),
        iface.into(),
        "peer".into(),
        peer.public_key_base64.clone(),
        "allowed-ips".into(),
        format!("{}/32", peer.allowed_ip),
    ];
    if let Some(ep) = peer.endpoint {
        args.push("endpoint".into());
        args.push(ep.to_string());
        args.push("persistent-keepalive".into());
        args.push(WG_PERSISTENT_KEEPALIVE_SECS.to_string());
    }
    args
}

pub fn set_peer_endpoint_args(
    iface: &str,
    public_key_base64: &str,
    endpoint: SocketAddr,
) -> Vec<String> {
    vec![
        "set".into(),
        iface.into(),
        "peer".into(),
        public_key_base64.into(),
        "endpoint".into(),
        endpoint.to_string(),
        "persistent-keepalive".into(),
        WG_PERSISTENT_KEEPALIVE_SECS.to_string(),
    ]
}

/// Parse `wg show <iface> latest-handshakes`. Does not include private keys.
pub fn wg_latest_handshakes(iface: &str) -> Result<Vec<(String, u64)>, WgError> {
    let bin = find_wg()?;
    let out = Command::new(&bin)
        .args(["show", iface, "latest-handshakes"])
        .output()
        .map_err(|e| WgError::WgFailed {
            args: vec!["show".into(), iface.into(), "latest-handshakes".into()],
            stderr: e.to_string(),
        })?;
    if !out.status.success() {
        return Err(WgError::WgFailed {
            args: vec!["show".into(), iface.into(), "latest-handshakes".into()],
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    Ok(parse_latest_handshakes(&String::from_utf8_lossy(&out.stdout)))
}

pub fn parse_latest_handshakes(text: &str) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(pk) = parts.next() else { continue };
        let Some(ts) = parts.next() else { continue };
        if let Ok(unix) = ts.parse::<u64>() {
            out.push((pk.to_string(), unix));
        }
    }
    out
}

/// Best-effort primary IPv4 from `ip route get 1.1.1.1` (`src` field).
pub fn primary_ipv4() -> Option<Ipv4Addr> {
    source_ipv4_toward(Ipv4Addr::new(1, 1, 1, 1))
}

/// Source IPv4 the kernel would use to reach `dest` (`ip route get`).
pub fn source_ipv4_toward(dest: Ipv4Addr) -> Option<Ipv4Addr> {
    let bin = find_ip().ok()?;
    let out = Command::new(bin)
        .args(["-4", "route", "get", &dest.to_string()])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_src_ipv4(&String::from_utf8_lossy(&out.stdout))
}

pub fn parse_src_ipv4(text: &str) -> Option<Ipv4Addr> {
    let mut toks = text.split_whitespace();
    while let Some(t) = toks.next() {
        if t == "src" {
            return toks.next().and_then(|s| s.parse().ok());
        }
    }
    None
}

fn is_overlay_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 10 && o[1] == 42 && o[2] == 0
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfAddr {
    pub iface: String,
    pub ip: Ipv4Addr,
}

/// Parse `ip -4 -o addr show` into interface addresses.
pub fn parse_if_addrs(text: &str) -> Vec<IfAddr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut toks = line.split_whitespace();
        let Some(_idx) = toks.next() else { continue };
        let Some(iface) = toks.next() else { continue };
        while let Some(t) = toks.next() {
            if t != "inet" {
                continue;
            }
            if let Some(cidr) = toks.next() {
                let addr = cidr.split('/').next().unwrap_or(cidr);
                if let Ok(ip) = addr.parse::<Ipv4Addr>() {
                    out.push(IfAddr {
                        iface: iface.trim_end_matches(':').to_string(),
                        ip,
                    });
                }
            }
            break;
        }
    }
    out
}

pub fn parse_local_ipv4s(text: &str) -> Vec<Ipv4Addr> {
    parse_if_addrs(text).into_iter().map(|a| a.ip).collect()
}

fn lan_score(iface: &str, ip: Ipv4Addr, default_src: Option<Ipv4Addr>) -> i32 {
    if ip.is_loopback() || is_overlay_ipv4(ip) || !ip.is_private() {
        return i32::MIN / 2;
    }
    let name = iface.to_ascii_lowercase();
    let o = ip.octets();
    let mut s = 10;
    if name.starts_with("vboxnet") || name.starts_with("vmnet") || name.contains("hostonly") {
        s += 100;
    }
    // VirtualBox default host-only (192.168.56.0/24)
    if o[0] == 192 && o[1] == 168 && o[2] == 56 {
        s += 80;
    }
    if name.starts_with("virbr") {
        s += 40;
    }
    if Some(ip) == default_src {
        s -= 25;
    }
    if name.starts_with("docker") || name.starts_with("br-") || name == "lxcbr0" || name == "cni0" {
        s -= 60;
    }
    if name.starts_with("tun") || name.starts_with("wg") || name.starts_with("mynet") {
        s -= 100;
    }
    s
}

/// Private LAN IPv4s, best first (host-only / VM NICs before Wi-Fi).
pub fn rank_lan_ipv4s(addrs: &[IfAddr], default_src: Option<Ipv4Addr>) -> Vec<Ipv4Addr> {
    let mut scored: Vec<(i32, Ipv4Addr)> = addrs
        .iter()
        .map(|a| (lan_score(&a.iface, a.ip, default_src), a.ip))
        .filter(|(s, _)| *s > i32::MIN / 4)
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0));
    let mut out = Vec::new();
    for (_, ip) in scored {
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

/// Address to put first in an invite (VirtualBox host-only when present).
pub fn pick_advertise_ipv4() -> Option<Ipv4Addr> {
    pick_lan_ipv4s().into_iter().next()
}

/// All ranked LAN IPv4s for the invite (joiner tries them until one answers).
pub fn pick_lan_ipv4s() -> Vec<Ipv4Addr> {
    let addrs = local_if_addrs();
    let wan = primary_ipv4();
    rank_lan_ipv4s(&addrs, wan)
}

fn local_if_addrs() -> Vec<IfAddr> {
    let Ok(bin) = find_ip() else {
        return Vec::new();
    };
    let Ok(out) = Command::new(bin).args(["-4", "-o", "addr", "show"]).output() else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    parse_if_addrs(&String::from_utf8_lossy(&out.stdout))
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

    #[test]
    fn endpoint_update_does_not_include_private_key() {
        let args = set_peer_endpoint_args(
            "mynet0",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "203.0.113.8:51820".parse().unwrap(),
        );
        assert!(args.contains(&"203.0.113.8:51820".to_string()));
        assert!(!args.iter().any(|a| a.contains("private-key")));
        assert_eq!(args[3], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        assert!(args.contains(&WG_PERSISTENT_KEEPALIVE_SECS.to_string()));
    }

    #[test]
    fn parse_handshake_lines() {
        let text = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\t1700000000\n";
        let rows = parse_latest_handshakes(text);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1, 1_700_000_000);
    }

    #[test]
    fn parse_src_from_ip_route_get() {
        let sample = "1.1.1.1 via 192.168.1.1 dev wlp62s0 src 192.168.1.50 uid 1000\n";
        assert_eq!(
            parse_src_ipv4(sample).unwrap(),
            Ipv4Addr::new(192, 168, 1, 50)
        );
    }

    #[test]
    fn parse_ip_dash_o_addr() {
        let text = "\
2: wlp62s0    inet 192.168.1.50/24 brd 192.168.1.255 scope global wlp62s0
18: vboxnet0    inet 192.168.56.1/24 brd 192.168.56.255 scope global vboxnet0
1: lo    inet 127.0.0.1/8 scope host lo
";
        let ips = parse_local_ipv4s(text);
        assert!(ips.contains(&Ipv4Addr::new(192, 168, 1, 50)));
        assert!(ips.contains(&Ipv4Addr::new(192, 168, 56, 1)));
        assert!(ips.contains(&Ipv4Addr::new(127, 0, 0, 1)));
    }

    #[test]
    fn host_only_ranks_ahead_of_wifi() {
        let addrs = parse_if_addrs(
            "\
2: wlp62s0    inet 192.168.1.50/24 brd 192.168.1.255 scope global wlp62s0
18: vboxnet0    inet 192.168.56.1/24 brd 192.168.56.255 scope global vboxnet0
1: lo    inet 127.0.0.1/8 scope host lo
",
        );
        let ranked = rank_lan_ipv4s(&addrs, Some(Ipv4Addr::new(192, 168, 1, 50)));
        assert_eq!(ranked[0], Ipv4Addr::new(192, 168, 56, 1));
        assert!(ranked.contains(&Ipv4Addr::new(192, 168, 1, 50)));
        assert!(!ranked.contains(&Ipv4Addr::new(127, 0, 0, 1)));
    }
}
