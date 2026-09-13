//! Two-peer UDP relay (Phase 13).
//!
//! Forwards opaque datagrams between the last two source addresses that sent
//! traffic. The relay does not need keys and must not inspect payloads.
//!
//! This matches kernel WireGuard for **exactly two** nodes: both set `endpoint`
//! to the relay. A third peer cannot be demuxed (WG packets have no extra
//! dest header). Mesh relay is out of scope.

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

#[derive(Clone, Debug, Default)]
pub struct PairTable {
    a: Option<SocketAddr>,
    b: Option<SocketAddr>,
}

impl PairTable {
    pub fn learn(&mut self, src: SocketAddr) {
        if self.a == Some(src) || self.b == Some(src) {
            return;
        }
        if self.a.is_none() {
            self.a = Some(src);
        } else if self.b.is_none() {
            self.b = Some(src);
        }
        // A third distinct source is ignored (cannot demux).
    }

    pub fn other(&self, src: SocketAddr) -> Option<SocketAddr> {
        match (self.a, self.b) {
            (Some(a), Some(b)) if src == a => Some(b),
            (Some(a), Some(b)) if src == b => Some(a),
            _ => None,
        }
    }

    pub fn pair_count(&self) -> usize {
        self.a.is_some() as usize + self.b.is_some() as usize
    }
}

/// Copy `buf` to the other peer if both sides have been seen.
/// Returns the destination if a datagram was forwarded.
pub fn forward(table: &mut PairTable, src: SocketAddr, buf: &[u8], sock: &UdpSocket) -> std::io::Result<Option<SocketAddr>> {
    table.learn(src);
    if let Some(dst) = table.other(src) {
        sock.send_to(buf, dst)?;
        return Ok(Some(dst));
    }
    Ok(None)
}

pub fn bind_and_run(bind: &str) -> std::io::Result<()> {
    let sock = UdpSocket::bind(bind)?;
    sock.set_read_timeout(Some(Duration::from_millis(500)))?;
    tracing::info!(
        %bind,
        "pair UDP relay (opaque packets only; two peers max; not the coordinator)"
    );
    let mut table = PairTable::default();
    let mut buf = [0u8; 2048];
    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, src)) => {
                match forward(&mut table, src, &buf[..n], &sock) {
                    Ok(Some(dst)) => tracing::debug!(%src, %dst, bytes = n, "forwarded"),
                    Ok(None) => tracing::debug!(%src, bytes = n, "waiting for the other peer"),
                    Err(e) => tracing::warn!(error = %e, "forward failed"),
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn other_is_none_until_two_peers() {
        let mut t = PairTable::default();
        let a: SocketAddr = "127.0.0.1:1".parse().unwrap();
        t.learn(a);
        assert!(t.other(a).is_none());
        assert_eq!(t.pair_count(), 1);
    }

    #[test]
    fn forwards_bytes_unchanged_and_needs_no_keys() {
        let server = match UdpSocket::bind("127.0.0.1:0") {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(e) => panic!("{e}"),
        };
        server.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let addr = server.local_addr().unwrap();
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        a.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        b.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

        let mut table = PairTable::default();
        let mut buf = [0u8; 256];
        let secret = b"ciphertext-not-for-the-relay";
        a.send_to(secret, addr).unwrap();
        let (n, src) = server.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], secret);
        assert!(forward(&mut table, src, &buf[..n], &server).unwrap().is_none());

        b.send_to(b"hello-from-b", addr).unwrap();
        let (n, src) = server.recv_from(&mut buf).unwrap();
        let dst = forward(&mut table, src, &buf[..n], &server).unwrap();
        assert!(dst.is_some());
        let (n, from) = a.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello-from-b");
        assert_eq!(from, addr);
        assert!(!std::str::from_utf8(&buf[..n]).unwrap().contains("private"));
    }

    #[test]
    fn third_source_is_not_a_pair_member() {
        let mut t = PairTable::default();
        let a: SocketAddr = "10.0.0.1:1".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:1".parse().unwrap();
        let c: SocketAddr = "10.0.0.3:1".parse().unwrap();
        t.learn(a);
        t.learn(b);
        t.learn(c);
        assert_eq!(t.other(a), Some(b));
        assert!(t.other(c).is_none());
    }
}
