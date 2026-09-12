//! Shared constants and local paths for mynet.
//!
//! This crate is the control-plane foundation: names, overlay defaults, and
//! where the node stores local state. It does not move VPN packets.
//!
//! Keep these layers distinct. Do not collapse them into one concept:
//!
//! - **Identity** — who is this peer? (public key / peer ID)
//! - **Discovery** — where is the peer reachable? (UDP endpoint)
//! - **NAT traversal** — can two peers reach each other directly?
//! - **Transport** — how do encrypted packets move? (UDP)
//! - **Virtual networking** — how Linux traffic enters the overlay (TUN)
//! - **Encryption** — how payloads are protected (kernel WireGuard)

use std::path::{Path, PathBuf};

/// CLI and package name.
pub const APP_NAME: &str = "mynet";

/// Package version from Cargo.toml.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default Linux TUN / WireGuard interface name.
pub const DEFAULT_INTERFACE: &str = "mynet0";

/// First overlay network. IPv4 only in this project stage.
pub const DEFAULT_OVERLAY_PREFIX: &str = "10.42.0.0/24";

/// Default listen/transport port for later UDP / WireGuard phases.
pub const DEFAULT_LISTEN_PORT: u16 = 51820;

/// Environment override for the config directory. Used by tests.
pub const CONFIG_DIR_ENV: &str = "MYNET_CONFIG_DIR";

/// Directory for local configuration and identity.
///
/// Resolution order:
/// 1. `MYNET_CONFIG_DIR` if set and non-empty
/// 2. `$XDG_CONFIG_HOME/mynet` via `dirs::config_dir`
/// 3. `./mynet` as a last resort
pub fn config_dir() -> PathBuf {
    if let Ok(dir) = std::env::var(CONFIG_DIR_ENV) {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(APP_NAME)
}

/// Path of the persistent identity file.
pub fn identity_path() -> PathBuf {
    identity_path_in(&config_dir())
}

/// Identity file inside an explicit config directory.
pub fn identity_path_in(dir: &Path) -> PathBuf {
    dir.join("identity.toml")
}

/// Path of the trusted-peer list (Phase 2).
pub fn peers_path() -> PathBuf {
    config_dir().join("peers.toml")
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
    }

    #[test]
    fn config_dir_env_override() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(CONFIG_DIR_ENV, "/tmp/mynet-test-config");
        assert_eq!(config_dir(), PathBuf::from("/tmp/mynet-test-config"));
        std::env::remove_var(CONFIG_DIR_ENV);
    }
}
