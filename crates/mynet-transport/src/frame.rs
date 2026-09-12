//! Experimental plaintext overlay framing.
//!
//! Magic prefix so random UDP is not injected into TUN. This is not
//! authentication and not encryption.

pub const MAGIC: &[u8; 4] = b"MYN1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FrameError {
    #[error("UDP payload too short")]
    Truncated,
    #[error("UDP payload is not a mynet plaintext overlay datagram")]
    BadMagic,
}

pub fn encode(ipv4: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAGIC.len() + ipv4.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(ipv4);
    out
}

pub fn decode(buf: &[u8]) -> Result<&[u8], FrameError> {
    if buf.len() < MAGIC.len() {
        return Err(FrameError::Truncated);
    }
    if &buf[..4] != MAGIC {
        return Err(FrameError::BadMagic);
    }
    Ok(&buf[4..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let pkt = [0x45, 0, 0, 20];
        let enc = encode(&pkt);
        assert_eq!(decode(&enc).unwrap(), &pkt);
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(decode(b"HELLO"), Err(FrameError::BadMagic));
        assert_eq!(decode(b"MY"), Err(FrameError::Truncated));
    }
}
