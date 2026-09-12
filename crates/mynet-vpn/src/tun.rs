//! Linux TUN via `/dev/net/tun` (IFF_TUN | IFF_NO_PI).
//!
//! Address configuration uses the system `ip` command. Creating the device
//! requires `CAP_NET_ADMIN`. Closing the file descriptor removes a
//! non-persistent TUN.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::process::Command;

const IFNAMSIZ: usize = 16;
/// From linux/if_tun.h: _IOW('T', 202, int)
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

#[derive(Debug, thiserror::Error)]
pub enum TunError {
    #[error("failed to open /dev/net/tun: {0}")]
    Open(#[source] io::Error),
    #[error("TUNSETIFF failed: {0}")]
    SetIff(#[source] io::Error),
    #[error("need CAP_NET_ADMIN or root to create a TUN interface (try: sudo mynet tun-test)")]
    Permission,
    #[error("interface name {0:?} is invalid")]
    BadName(String),
    #[error("`ip` command not found")]
    IpMissing,
    #[error("ip {args:?} failed: {stderr}")]
    IpFailed { args: Vec<String>, stderr: String },
    #[error("TUN I/O: {0}")]
    Io(#[from] io::Error),
}

/// An open Linux TUN device.
pub struct TunDevice {
    file: File,
    name: String,
}

impl TunDevice {
    /// Create (or attach to) a TUN named `name` (max 15 chars).
    pub fn open(name: &str) -> Result<Self, TunError> {
        validate_name(name)?;
        let tun = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|e| {
                if e.kind() == io::ErrorKind::PermissionDenied {
                    TunError::Permission
                } else {
                    TunError::Open(e)
                }
            })?;

        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        for (i, b) in name.as_bytes().iter().enumerate() {
            ifr.ifr_name[i] = *b as libc::c_char;
        }
        ifr.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;

        let rc = unsafe { libc::ioctl(tun.as_raw_fd(), TUNSETIFF, &mut ifr) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EPERM) || err.kind() == io::ErrorKind::PermissionDenied
            {
                return Err(TunError::Permission);
            }
            return Err(TunError::SetIff(err));
        }

        let assigned = c_ifname(&ifr.ifr_name);
        tracing::info!(interface = %assigned, "TUN opened");
        Ok(TunDevice {
            file: tun,
            name: assigned,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Assign IPv4 and bring the link up. Uses `/usr/sbin/ip` or `ip`.
    pub fn configure_ipv4(&self, addr: Ipv4Addr, prefix: u8) -> Result<(), TunError> {
        let cidr = format!("{addr}/{prefix}");
        ip(&["addr", "replace", &cidr, "dev", &self.name])?;
        ip(&["link", "set", "dev", &self.name, "up"])?;
        tracing::info!(interface = %self.name, cidr = %cidr, "TUN configured");
        Ok(())
    }

    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }

    pub fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        tracing::info!(interface = %self.name, "TUN closed");
    }
}

fn validate_name(name: &str) -> Result<(), TunError> {
    if name.is_empty()
        || name.len() >= IFNAMSIZ
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(TunError::BadName(name.to_string()));
    }
    Ok(())
}

fn c_ifname(raw: &[libc::c_char; IFNAMSIZ]) -> String {
    let bytes: Vec<u8> = raw
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

pub(crate) fn ip(args: &[&str]) -> Result<(), TunError> {
    let bin = find_ip()?;
    let out = Command::new(&bin).args(args).output().map_err(TunError::Io)?;
    if out.status.success() {
        return Ok(());
    }
    Err(TunError::IpFailed {
        args: args.iter().map(|s| (*s).to_string()).collect(),
        stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
    })
}

pub(crate) fn find_ip() -> Result<std::path::PathBuf, TunError> {
    for candidate in ["/usr/sbin/ip", "/sbin/ip", "ip"] {
        if candidate.starts_with('/') {
            if Path::new(candidate).exists() {
                return Ok(Path::new(candidate).to_path_buf());
            }
        } else if Command::new(candidate).arg("-V").output().is_ok() {
            return Ok(Path::new(candidate).to_path_buf());
        }
    }
    Err(TunError::IpMissing)
}

/// Privilege probe used by tests and `mynet doctor`-style commands.
pub fn tun_available() -> Result<(), TunError> {
    // Open and immediately drop. A unique name avoids colliding with mynet0.
    let name = format!("mynettst{}", std::process::id() % 1000);
    let _dev = TunDevice::open(&name)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_names() {
        assert!(TunDevice::open("").is_err());
        assert!(TunDevice::open("this-name-is-way-too-long").is_err());
        assert!(TunDevice::open("bad name").is_err());
    }

    #[test]
    fn open_without_cap_is_permission_or_ok() {
        match TunDevice::open("mynettst0") {
            Err(TunError::Permission) | Err(TunError::Open(_)) | Err(TunError::SetIff(_)) => {}
            Ok(dev) => {
                // Privileged environment: device must have the requested name.
                assert_eq!(dev.name(), "mynettst0");
            }
            Err(other) => panic!("unexpected error: {other}"),
        }
    }
}
