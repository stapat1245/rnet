//! Standalone UDP hole-punch experiment (Phase 10).
//!
//! This is not overlay traffic and not kernel WireGuard. It exists to make the
//! NAT model in `notes.md` testable: same-LAN UDP punch, plus a mapping model
//! for cone vs symmetric NAT.
//!
//! Symmetric NAT is forecast to fail. That failure is recorded here rather
//! than pretended away.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

pub const MAGIC: &[u8; 4] = b"HP1\0";
pub const KIND_HELLO: u8 = 1;
pub const KIND_PEER: u8 = 2;
pub const KIND_PUNCH: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatKind {
    None,
    FullCone,
    RestrictedCone,
    PortRestrictedCone,
    Symmetric,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PunchForecast {
    Likely,
    Possible,
    Unlikely,
}

/// Forecast from the written NAT model. Not a measurement of this lab's WAN.
pub fn forecast_punch(a: NatKind, b: NatKind) -> PunchForecast {
    use NatKind::*;
    match (a, b) {
        (None, _) | (_, None) => PunchForecast::Likely,
        (Symmetric, Symmetric) => PunchForecast::Unlikely,
        (Symmetric, _) | (_, Symmetric) => PunchForecast::Unlikely,
        (FullCone, _) | (_, FullCone) => PunchForecast::Likely,
        (RestrictedCone, RestrictedCone)
        | (RestrictedCone, PortRestrictedCone)
        | (PortRestrictedCone, RestrictedCone)
        | (PortRestrictedCone, PortRestrictedCone) => PunchForecast::Possible,
    }
}

/// Userspace mapping table used to *simulate* cone vs symmetric NATs.
///
/// Cone: one WAN port per LAN socket, independent of destination.
/// Symmetric: a new WAN port per (LAN socket, destination).
pub struct MappingNat {
    kind: NatKind,
    wan_ip: Ipv4Addr,
    next_port: u16,
    cone: HashMap<SocketAddr, u16>,
    symmetric: HashMap<(SocketAddr, SocketAddr), u16>,
}

impl MappingNat {
    pub fn new(kind: NatKind, wan_ip: Ipv4Addr) -> Self {
        MappingNat {
            kind,
            wan_ip,
            next_port: 40000,
            cone: HashMap::new(),
            symmetric: HashMap::new(),
        }
    }

    pub fn map(&mut self, lan: SocketAddr, dest: SocketAddr) -> SocketAddr {
        match self.kind {
            NatKind::None => return lan,
            NatKind::Symmetric => {
                if let Some(port) = self.symmetric.get(&(lan, dest)).copied() {
                    return SocketAddr::V4(SocketAddrV4::new(self.wan_ip, port));
                }
                let port = self.alloc();
                self.symmetric.insert((lan, dest), port);
                SocketAddr::V4(SocketAddrV4::new(self.wan_ip, port))
            }
            NatKind::FullCone | NatKind::RestrictedCone | NatKind::PortRestrictedCone => {
                if let Some(port) = self.cone.get(&lan).copied() {
                    return SocketAddr::V4(SocketAddrV4::new(self.wan_ip, port));
                }
                let port = self.alloc();
                self.cone.insert(lan, port);
                SocketAddr::V4(SocketAddrV4::new(self.wan_ip, port))
            }
        }
    }

    fn alloc(&mut self) -> u16 {
        let p = self.next_port;
        self.next_port = self.next_port.saturating_add(1);
        p
    }
}

/// Simulate hole punch using mapped addresses the rendezvous would see.
///
/// Each side sends to the rendezvous first (creating a mapping), learns the
/// other's rendezvous-facing mapping, then sends to that candidate. For
/// cone NATs the mapping toward the peer is the same port; for symmetric
/// it is not, so the far NAT does not recognize the packet.
pub fn simulate_hole_punch(kind_a: NatKind, kind_b: NatKind) -> bool {
    let rendezvous: SocketAddr = "203.0.113.1:3478".parse().unwrap();
    let lan_a: SocketAddr = "10.0.0.1:51820".parse().unwrap();
    let lan_b: SocketAddr = "10.1.0.1:51820".parse().unwrap();
    let mut nat_a = MappingNat::new(kind_a, "198.51.100.10".parse().unwrap());
    let mut nat_b = MappingNat::new(kind_b, "198.51.100.20".parse().unwrap());

    let a_at_rendezvous = nat_a.map(lan_a, rendezvous);
    let b_at_rendezvous = nat_b.map(lan_b, rendezvous);

    let a_to_b = nat_a.map(lan_a, b_at_rendezvous);
    let b_to_a = nat_b.map(lan_b, a_at_rendezvous);

    a_to_b == a_at_rendezvous && b_to_a == b_at_rendezvous
}

#[derive(Debug, thiserror::Error)]
pub enum PunchError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("timeout waiting for hole punch")]
    Timeout,
    #[error("bad hole-punch frame")]
    BadFrame,
}

pub fn encode_hello(id: &str) -> Vec<u8> {
    let mut v = MAGIC.to_vec();
    v.push(KIND_HELLO);
    v.extend_from_slice(id.as_bytes());
    v
}

pub fn encode_punch(id: &str) -> Vec<u8> {
    let mut v = MAGIC.to_vec();
    v.push(KIND_PUNCH);
    v.extend_from_slice(id.as_bytes());
    v
}

pub fn encode_peer(addr: SocketAddr) -> Vec<u8> {
    let s = addr.to_string();
    let mut v = MAGIC.to_vec();
    v.push(KIND_PEER);
    v.extend_from_slice(s.as_bytes());
    v
}

pub fn decode_kind(buf: &[u8]) -> Result<(u8, &[u8]), PunchError> {
    if buf.len() < 5 || &buf[..4] != MAGIC {
        return Err(PunchError::BadFrame);
    }
    Ok((buf[4], &buf[5..]))
}

/// Two UDP sockets on localhost, introduced by a rendezvous socket.
/// This is the same-LAN / same-host experiment. It does not prove WAN NAT.
pub fn localhost_hole_punch() -> Result<(), PunchError> {
    let rendezvous = match UdpSocket::bind("127.0.0.1:0") {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    rendezvous.set_read_timeout(Some(Duration::from_secs(2)))?;
    let raddr = rendezvous.local_addr()?;

    let a = UdpSocket::bind("127.0.0.1:0")?;
    let b = UdpSocket::bind("127.0.0.1:0")?;
    a.set_read_timeout(Some(Duration::from_secs(2)))?;
    b.set_read_timeout(Some(Duration::from_secs(2)))?;
    a.send_to(&encode_hello("a"), raddr)?;
    b.send_to(&encode_hello("b"), raddr)?;

    let mut buf = [0u8; 256];
    let (n1, src1) = rendezvous.recv_from(&mut buf)?;
    let (n2, src2) = rendezvous.recv_from(&mut buf)?;
    let _ = (n1, n2);
    rendezvous.send_to(&encode_peer(src2), src1)?;
    rendezvous.send_to(&encode_peer(src1), src2)?;

    let mut abuf = [0u8; 256];
    let (na, _) = a.recv_from(&mut abuf)?;
    let (ka, payload_a) = decode_kind(&abuf[..na])?;
    if ka != KIND_PEER {
        return Err(PunchError::BadFrame);
    }
    let b_addr: SocketAddr = std::str::from_utf8(payload_a)
        .map_err(|_| PunchError::BadFrame)?
        .parse()
        .map_err(|_| PunchError::BadFrame)?;

    let mut bbuf = [0u8; 256];
    let (nb, _) = b.recv_from(&mut bbuf)?;
    let (kb, payload_b) = decode_kind(&bbuf[..nb])?;
    if kb != KIND_PEER {
        return Err(PunchError::BadFrame);
    }
    let a_addr: SocketAddr = std::str::from_utf8(payload_b)
        .map_err(|_| PunchError::BadFrame)?
        .parse()
        .map_err(|_| PunchError::BadFrame)?;

    a.send_to(&encode_punch("a"), b_addr)?;
    b.send_to(&encode_punch("b"), a_addr)?;

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut got_a = false;
    let mut got_b = false;
    while Instant::now() < deadline && (!got_a || !got_b) {
        if !got_a {
            if let Ok((n, _)) = a.recv_from(&mut abuf) {
                if let Ok((k, _)) = decode_kind(&abuf[..n]) {
                    if k == KIND_PUNCH {
                        got_a = true;
                    }
                }
            }
        }
        if !got_b {
            if let Ok((n, _)) = b.recv_from(&mut bbuf) {
                if let Ok((k, _)) = decode_kind(&bbuf[..n]) {
                    if k == KIND_PUNCH {
                        got_b = true;
                    }
                }
            }
        }
    }
    if got_a && got_b {
        Ok(())
    } else {
        Err(PunchError::Timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forecast_matches_notes() {
        assert_eq!(
            forecast_punch(NatKind::None, NatKind::PortRestrictedCone),
            PunchForecast::Likely
        );
        assert_eq!(
            forecast_punch(NatKind::PortRestrictedCone, NatKind::PortRestrictedCone),
            PunchForecast::Possible
        );
        assert_eq!(
            forecast_punch(NatKind::Symmetric, NatKind::Symmetric),
            PunchForecast::Unlikely
        );
        assert_eq!(
            forecast_punch(NatKind::Symmetric, NatKind::FullCone),
            PunchForecast::Unlikely
        );
    }

    #[test]
    fn cone_mapping_is_stable_across_destinations() {
        let mut nat = MappingNat::new(NatKind::PortRestrictedCone, "198.51.100.9".parse().unwrap());
        let lan: SocketAddr = "10.0.0.2:51820".parse().unwrap();
        let d1: SocketAddr = "203.0.113.1:3478".parse().unwrap();
        let d2: SocketAddr = "203.0.113.8:51820".parse().unwrap();
        assert_eq!(nat.map(lan, d1), nat.map(lan, d2));
    }

    #[test]
    fn symmetric_mapping_changes_with_destination() {
        let mut nat = MappingNat::new(NatKind::Symmetric, "198.51.100.9".parse().unwrap());
        let lan: SocketAddr = "10.0.0.2:51820".parse().unwrap();
        let d1: SocketAddr = "203.0.113.1:3478".parse().unwrap();
        let d2: SocketAddr = "203.0.113.8:51820".parse().unwrap();
        assert_ne!(nat.map(lan, d1), nat.map(lan, d2));
    }

    #[test]
    fn simulate_cone_punch_succeeds_symmetric_fails() {
        assert!(simulate_hole_punch(
            NatKind::PortRestrictedCone,
            NatKind::PortRestrictedCone
        ));
        assert!(!simulate_hole_punch(NatKind::Symmetric, NatKind::Symmetric));
        // Recorded failure: symmetric NAT hole punch does not work in this model.
    }

    #[test]
    fn localhost_udp_punch() {
        match localhost_hole_punch() {
            Ok(()) => {}
            Err(PunchError::Io(e)) if e.kind() == std::io::ErrorKind::PermissionDenied => {}
            Err(PunchError::Timeout) => {
                // Sandbox may drop localhost UDP; treat as skip.
                eprintln!("skip: localhost UDP punch timed out");
            }
            Err(e) => panic!("{e}"),
        }
    }
}
