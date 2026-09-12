//! Plaintext TUN ↔ UDP forwarding (Phase 4 learning path).
//!
//! Not the final protocol. Source/destination overlay IPs are checked against
//! the local address and the trusted-peer map, but anyone who can send UDP can
//! still spoof those headers. WireGuard (Phase 5) authenticates peers.

use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use mynet_vpn::{parse_ipv4, TunDevice};

use crate::frame::{decode, encode};

#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    #[error("I/O: {0}")]
    Io(#[from] io::Error),
    #[error("poll failed: {0}")]
    Poll(io::Error),
}

/// Decide where an outbound overlay packet should go.
///
/// Returns None if the packet should be dropped (wrong version, not for a
/// known peer, spoofed source).
pub fn forward_outbound(
    packet: &[u8],
    local_ip: Ipv4Addr,
    routes: &HashMap<Ipv4Addr, SocketAddr>,
) -> Option<SocketAddr> {
    let info = parse_ipv4(packet).ok()?;
    if info.src != local_ip {
        tracing::debug!(src = %info.src, "drop outbound: source is not local overlay IP");
        return None;
    }
    match routes.get(&info.dst).copied() {
        Some(ep) => Some(ep),
        None => {
            tracing::debug!(dst = %info.dst, "drop outbound: no trusted peer route");
            None
        }
    }
}

/// Inject a received overlay packet into TUN only if it is IPv4, destined to
/// us, and sourced from a trusted overlay IP.
pub fn accept_inbound(
    packet: &[u8],
    local_ip: Ipv4Addr,
    routes: &HashMap<Ipv4Addr, SocketAddr>,
) -> bool {
    match parse_ipv4(packet) {
        Ok(info) => {
            if info.dst != local_ip {
                tracing::debug!(dst = %info.dst, "drop inbound: dest is not local overlay IP");
                return false;
            }
            if !routes.contains_key(&info.src) {
                tracing::debug!(src = %info.src, "drop inbound: source is not a trusted peer");
                return false;
            }
            true
        }
        Err(_) => false,
    }
}

/// Blocking poll loop. Exits when `stop` is true.
pub fn run_plain_loop(
    tun: &mut TunDevice,
    sock: &UdpSocket,
    local_ip: Ipv4Addr,
    routes: &HashMap<Ipv4Addr, SocketAddr>,
    stop: &AtomicBool,
) -> Result<(), ForwardError> {
    sock.set_nonblocking(true)?;
    let tun_fd = tun.as_raw_fd();
    let udp_fd = {
        use std::os::unix::io::AsRawFd;
        sock.as_raw_fd()
    };

    let mut tun_buf = [0u8; 2048];
    let mut udp_buf = [0u8; 2048];

    while !stop.load(Ordering::Relaxed) {
        let mut fds = [
            libc::pollfd {
                fd: tun_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: udp_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 250) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(ForwardError::Poll(err));
        }

        if fds[0].revents & libc::POLLIN != 0 {
            match tun.read(&mut tun_buf) {
                Ok(0) => {}
                Ok(n) => {
                    if let Some(dst) = forward_outbound(&tun_buf[..n], local_ip, routes) {
                        let framed = encode(&tun_buf[..n]);
                        if let Err(e) = sock.send_to(&framed, dst) {
                            tracing::warn!(error = %e, "UDP send failed");
                        } else if let Ok(info) = parse_ipv4(&tun_buf[..n]) {
                            tracing::debug!(
                                dst = %info.dst,
                                proto = info.proto,
                                endpoint = %dst,
                                "TUN → UDP"
                            );
                        }
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }

        if fds[1].revents & libc::POLLIN != 0 {
            match sock.recv_from(&mut udp_buf) {
                Ok((n, _from)) => {
                    if let Ok(pkt) = decode(&udp_buf[..n]) {
                        if accept_inbound(pkt, local_ip, routes) {
                            if let Err(e) = tun.write(pkt) {
                                tracing::warn!(error = %e, "TUN write failed");
                            } else if let Ok(info) = parse_ipv4(pkt) {
                                tracing::debug!(
                                    src = %info.src,
                                    proto = info.proto,
                                    "UDP → TUN"
                                );
                            }
                        }
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
    }
    let _ = Duration::from_millis(0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV4;

    fn pkt(src: Ipv4Addr, dst: Ipv4Addr) -> [u8; 20] {
        let mut p = [0u8; 20];
        p[0] = 0x45;
        p[9] = 1;
        let s = src.octets();
        let d = dst.octets();
        p[12..16].copy_from_slice(&s);
        p[16..20].copy_from_slice(&d);
        p
    }

    fn routes() -> HashMap<Ipv4Addr, SocketAddr> {
        let mut m = HashMap::new();
        m.insert(
            Ipv4Addr::new(10, 42, 0, 2),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 51820)),
        );
        m
    }

    #[test]
    fn outbound_maps_trusted_dst() {
        let local = Ipv4Addr::new(10, 42, 0, 1);
        let p = pkt(local, Ipv4Addr::new(10, 42, 0, 2));
        let ep = forward_outbound(&p, local, &routes()).unwrap();
        assert_eq!(ep.port(), 51820);
    }

    #[test]
    fn outbound_drops_wrong_src() {
        let local = Ipv4Addr::new(10, 42, 0, 1);
        let p = pkt(Ipv4Addr::new(10, 42, 0, 9), Ipv4Addr::new(10, 42, 0, 2));
        assert!(forward_outbound(&p, local, &routes()).is_none());
    }

    #[test]
    fn inbound_accepts_trusted_src() {
        let local = Ipv4Addr::new(10, 42, 0, 1);
        let p = pkt(Ipv4Addr::new(10, 42, 0, 2), local);
        assert!(accept_inbound(&p, local, &routes()));
    }

    #[test]
    fn inbound_drops_unknown_src() {
        let local = Ipv4Addr::new(10, 42, 0, 1);
        let p = pkt(Ipv4Addr::new(10, 42, 0, 9), local);
        assert!(!accept_inbound(&p, local, &routes()));
    }

    #[test]
    fn udp_frame_round_trip_localhost() {
        let a = match UdpSocket::bind("127.0.0.1:0") {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skip: UDP bind denied in this environment");
                return;
            }
            Err(e) => panic!("{e}"),
        };
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let payload = pkt(Ipv4Addr::new(10, 42, 0, 1), Ipv4Addr::new(10, 42, 0, 2));
        let framed = encode(&payload);
        a.send_to(&framed, b.local_addr().unwrap()).unwrap();
        let mut buf = [0u8; 64];
        let (n, _) = b.recv_from(&mut buf).unwrap();
        assert_eq!(decode(&buf[..n]).unwrap(), &payload);
    }
}
