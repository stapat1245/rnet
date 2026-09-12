//! IPv4 header inspection for overlay forwarding.
//!
//! Does not interpret application payloads. Logs and routing use addresses
//! and protocol numbers only.

use std::net::Ipv4Addr;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Info {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub proto: u8,
    pub header_len: usize,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PacketError {
    #[error("packet shorter than an IPv4 header")]
    Truncated,
    #[error("not an IPv4 packet")]
    NotIpv4,
    #[error("IPv4 header length is invalid")]
    BadHeaderLen,
}

/// Parse a raw L3 IPv4 packet as delivered by a TUN with IFF_NO_PI.
pub fn parse_ipv4(buf: &[u8]) -> Result<Ipv4Info, PacketError> {
    if buf.len() < 20 {
        return Err(PacketError::Truncated);
    }
    if buf[0] >> 4 != 4 {
        return Err(PacketError::NotIpv4);
    }
    let header_len = ((buf[0] & 0x0f) as usize) * 4;
    if header_len < 20 || buf.len() < header_len {
        return Err(PacketError::BadHeaderLen);
    }
    Ok(Ipv4Info {
        src: Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]),
        dst: Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]),
        proto: buf[9],
        header_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> [u8; 20] {
        let mut p = [0u8; 20];
        p[0] = 0x45;
        p[9] = 1; // ICMP
        p[12] = 10;
        p[13] = 42;
        p[14] = 0;
        p[15] = 1;
        p[16] = 10;
        p[17] = 42;
        p[18] = 0;
        p[19] = 2;
        p
    }

    #[test]
    fn parses_src_dst_proto() {
        let info = parse_ipv4(&sample()).unwrap();
        assert_eq!(info.src, Ipv4Addr::new(10, 42, 0, 1));
        assert_eq!(info.dst, Ipv4Addr::new(10, 42, 0, 2));
        assert_eq!(info.proto, 1);
        assert_eq!(info.header_len, 20);
    }

    #[test]
    fn rejects_truncated() {
        assert_eq!(parse_ipv4(&[0x45, 0, 0]), Err(PacketError::Truncated));
    }

    #[test]
    fn rejects_ipv6_version() {
        let mut p = sample();
        p[0] = 0x60;
        assert_eq!(parse_ipv4(&p), Err(PacketError::NotIpv4));
    }
}
