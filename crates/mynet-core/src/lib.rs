//! Shared constants, paths, and the local trusted-peer set.
//!
//! Keep these layers distinct. Do not collapse them into one concept:
//!
//! - **Identity** — who is this peer? (`mynet-identity`, public key / peer ID)
//! - **Discovery** — where is the peer reachable? (UDP endpoint)
//! - **NAT traversal** — can two peers reach each other directly?
//! - **Transport** — how do encrypted packets move? (UDP)
//! - **Virtual networking** — how Linux traffic enters the overlay (TUN)
//! - **Encryption** — how payloads are protected (kernel WireGuard)
//!
//! This crate is control-plane support. VPN packets must never be routed
//! through a coordination server.

use std::path::{Path, PathBuf};

mod invite;
mod local;
mod peer;
mod session;

pub use invite::{Invite, InviteError, INVITE_PREFIX, INVITE_SYNC_SECS};
pub use local::{split_host_port, LocalConfig, LocalError};
pub use peer::{parse_endpoint, ApplyKind, Peer, PeerError, PeerList, PeerState};
pub use session::{
    SessionError, SessionEvent, SessionIoError, SessionRow, SessionTable, HANDSHAKE_TIMEOUT_SECS,
};

/// CLI and package name.
pub const APP_NAME: &str = "mynet";

/// Package version (from Cargo.toml).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default Linux TUN / WireGuard interface name.
pub const DEFAULT_INTERFACE: &str = "mynet0";

/// First overlay network. IPv4 only in this project stage.
pub const DEFAULT_OVERLAY_PREFIX: &str = "10.42.0.0/24";

/// Default listen/transport port for later UDP / WireGuard phases.
pub const DEFAULT_LISTEN_PORT: u16 = 51820;

/// Default TCP port for the optional coordination server (control plane only).
/// This is not the WireGuard data-plane port.
pub const DEFAULT_COORDINATOR_PORT: u16 = 9993;

/// Default UDP port for the optional pair relay (data-plane fallback).
/// Distinct from the coordinator TCP port and from WireGuard.
pub const DEFAULT_RELAY_PORT: u16 = 9994;

/// Default UDP port for the standalone hole-punch experiment.
pub const DEFAULT_HOLEPUNCH_PORT: u16 = 3478;

/// WireGuard persistent-keepalive (seconds). Also the NAT binding refresh
/// for the kernel WG socket.
pub const WG_PERSISTENT_KEEPALIVE_SECS: u16 = 25;

/// How often `mynet connect` re-registers with the coordinator.
pub const COORDINATOR_SYNC_SECS: u64 = 30;

/// Environment override for the config directory. Used by tests and `--config-dir`.
pub const CONFIG_DIR_ENV: &str = "MYNET_CONFIG_DIR";

/// Directory for local configuration and identity.
///
/// Resolution order:
/// 1. `MYNET_CONFIG_DIR` if set and non-empty
/// 2. Invoking user's `~/.config/mynet` when running under `sudo` (`SUDO_USER`)
/// 3. `$XDG_CONFIG_HOME/mynet` via `dirs::config_dir`
/// 4. `./mynet` as a last resort
pub fn config_dir() -> PathBuf {
    if let Ok(dir) = std::env::var(CONFIG_DIR_ENV) {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    if let Some(dir) = sudo_user_config_dir() {
        return dir;
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(APP_NAME)
}

fn euid_is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// `sudo mynet` must not look in `/root/.config/mynet` for identity created as a normal user.
fn sudo_user_config_dir() -> Option<PathBuf> {
    if !euid_is_root() {
        return None;
    }
    let user = std::env::var("SUDO_USER").ok()?;
    if user.is_empty() || user == "root" {
        return None;
    }
    Some(home_dir_of(&user)?.join(".config").join(APP_NAME))
}

fn home_dir_of(user: &str) -> Option<PathBuf> {
    let cname = std::ffi::CString::new(user).ok()?;
    let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut buf = vec![0u8; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwnam_r(
            cname.as_ptr(),
            pwd.as_mut_ptr(),
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    let dir = unsafe { std::ffi::CStr::from_ptr((*result).pw_dir) };
    let s = dir.to_str().ok()?;
    if s.is_empty() {
        return None;
    }
    Some(PathBuf::from(s))
}

/// Path of the persistent identity file.
pub fn identity_path() -> PathBuf {
    identity_path_in(&config_dir())
}

/// Identity file inside an explicit config directory.
pub fn identity_path_in(dir: &Path) -> PathBuf {
    dir.join("identity.toml")
}

/// Path of the trusted-peer list.
pub fn peers_path() -> PathBuf {
    peers_path_in(&config_dir())
}

/// Trusted-peer file inside an explicit config directory.
pub fn peers_path_in(dir: &Path) -> PathBuf {
    dir.join("peers.toml")
}

/// Local overlay settings (virtual IP, listen port, interface name).
pub fn local_path() -> PathBuf {
    local_path_in(&config_dir())
}

/// Local overlay settings inside an explicit config directory.
pub fn local_path_in(dir: &Path) -> PathBuf {
    dir.join("local.toml")
}

/// Live per-peer connection states while `mynet connect` is running.
/// Deleted on disconnect. Not identity; not a substitute for `peers.toml`.
pub fn session_path_in(dir: &Path) -> PathBuf {
    dir.join("session.toml")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Process-global env mutations must not run concurrently.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn identity_lives_under_config_dir() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(CONFIG_DIR_ENV);
        let dir = config_dir();
        assert_eq!(identity_path(), dir.join("identity.toml"));
        assert_eq!(peers_path(), dir.join("peers.toml"));
        assert_eq!(identity_path_in(&dir), dir.join("identity.toml"));
        assert_eq!(peers_path_in(&dir), dir.join("peers.toml"));
        assert_eq!(local_path_in(&dir), dir.join("local.toml"));
    }

    #[test]
    fn config_dir_env_override() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(CONFIG_DIR_ENV, "/tmp/mynet-test-config");
        assert_eq!(config_dir(), PathBuf::from("/tmp/mynet-test-config"));
        std::env::remove_var(CONFIG_DIR_ENV);
    }

    #[test]
    fn config_dir_env_wins_over_sudo_user() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev_sudo = std::env::var("SUDO_USER").ok();
        std::env::set_var(CONFIG_DIR_ENV, "/tmp/mynet-test-config");
        std::env::set_var("SUDO_USER", "nobody");
        assert_eq!(config_dir(), PathBuf::from("/tmp/mynet-test-config"));
        std::env::remove_var(CONFIG_DIR_ENV);
        match prev_sudo {
            Some(v) => std::env::set_var("SUDO_USER", v),
            None => std::env::remove_var("SUDO_USER"),
        }
    }
}
