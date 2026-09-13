//! Coordinator control-plane protocol.
//!
//! Frames are length-prefixed TOML over TCP. This is **not** the VPN data
//! path. There is no message type for overlay packets, and clients must never
//! send private keys.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
pub const KIND_REGISTER: &str = "register";
pub const KIND_DISCOVER: &str = "discover";
pub const KIND_ALLOCATE: &str = "allocate";
pub const KIND_OK: &str = "ok";
pub const KIND_ERROR: &str = "error";

const IO_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlRequest {
    pub kind: String,
    #[serde(default)]
    pub token: String,
    pub public_key: String,
    #[serde(default)]
    pub virtual_ip: String,
    #[serde(default)]
    pub listen_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

impl fmt::Debug for ControlRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControlRequest")
            .field("kind", &self.kind)
            .field("token", &"[redacted]")
            .field("public_key", &self.public_key)
            .field("virtual_ip", &self.virtual_ip)
            .field("listen_port", &self.listen_port)
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

impl ControlRequest {
    pub fn register(
        token: impl Into<String>,
        public_key: impl Into<String>,
        virtual_ip: impl Into<String>,
        listen_port: u16,
        endpoint: Option<String>,
    ) -> Self {
        ControlRequest {
            kind: KIND_REGISTER.to_string(),
            token: token.into(),
            public_key: public_key.into(),
            virtual_ip: virtual_ip.into(),
            listen_port,
            endpoint,
        }
    }

    pub fn discover(token: impl Into<String>, public_key: impl Into<String>) -> Self {
        ControlRequest {
            kind: KIND_DISCOVER.to_string(),
            token: token.into(),
            public_key: public_key.into(),
            virtual_ip: String::new(),
            listen_port: 0,
            endpoint: None,
        }
    }

    pub fn allocate(token: impl Into<String>, public_key: impl Into<String>) -> Self {
        ControlRequest {
            kind: KIND_ALLOCATE.to_string(),
            token: token.into(),
            public_key: public_key.into(),
            virtual_ip: String::new(),
            listen_port: 0,
            endpoint: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvertisedPeer {
    pub public_key: String,
    pub virtual_ip: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub last_seen_unix: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlResponse {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default)]
    pub peers: Vec<AdvertisedPeer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_ip: Option<String>,
}

impl ControlResponse {
    pub fn ok(peers: Vec<AdvertisedPeer>) -> Self {
        ControlResponse {
            kind: KIND_OK.to_string(),
            message: None,
            peers,
            assigned_ip: None,
        }
    }

    pub fn allocated(ip: impl Into<String>) -> Self {
        ControlResponse {
            kind: KIND_OK.to_string(),
            message: None,
            peers: Vec::new(),
            assigned_ip: Some(ip.into()),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        ControlResponse {
            kind: KIND_ERROR.to_string(),
            message: Some(message.into()),
            peers: Vec::new(),
            assigned_ip: None,
        }
    }

    pub fn is_ok(&self) -> bool {
        self.kind == KIND_OK
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("control-plane I/O: {0}")]
    Io(#[from] io::Error),
    #[error("control-plane frame too large ({0} bytes)")]
    FrameTooLarge(usize),
    #[error("control-plane frame is not valid UTF-8")]
    NotUtf8,
    #[error("control-plane TOML is malformed")]
    Malformed,
    #[error("coordinator error: {0}")]
    Remote(String),
    #[error("could not resolve coordinator {0}")]
    Unresolved(String),
}

pub fn encode_toml<T: Serialize>(value: &T) -> Result<String, ProtocolError> {
    toml::to_string(value).map_err(|_| ProtocolError::Malformed)
}

pub fn decode_toml<T: for<'de> Deserialize<'de>>(text: &str) -> Result<T, ProtocolError> {
    toml::from_str(text).map_err(|_| ProtocolError::Malformed)
}

pub fn write_frame(writer: &mut impl Write, body: &str) -> Result<(), ProtocolError> {
    let bytes = body.as_bytes();
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge(bytes.len()));
    }
    writer.write_all(&(bytes.len() as u32).to_be_bytes())?;
    writer.write_all(bytes)?;
    writer.flush()?;
    Ok(())
}

pub fn read_frame(reader: &mut impl Read) -> Result<String, ProtocolError> {
    let mut lenb = [0u8; 4];
    reader.read_exact(&mut lenb)?;
    let len = u32::from_be_bytes(lenb) as usize;
    if len == 0 || len > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    String::from_utf8(buf).map_err(|_| ProtocolError::NotUtf8)
}

/// One request / one response over a new TCP connection.
pub fn rpc(coordinator: &str, request: &ControlRequest) -> Result<ControlResponse, ProtocolError> {
    let addr = coordinator
        .trim()
        .to_socket_addrs()
        .map_err(|_| ProtocolError::Unresolved(coordinator.to_string()))?
        .next()
        .ok_or_else(|| ProtocolError::Unresolved(coordinator.to_string()))?;
    let mut stream = TcpStream::connect_timeout(&addr, IO_TIMEOUT)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    write_frame(&mut stream, &encode_toml(request)?)?;
    let body = read_frame(&mut stream)?;
    let response: ControlResponse = decode_toml(&body)?;
    if !response.is_ok() {
        return Err(ProtocolError::Remote(
            response
                .message
                .unwrap_or_else(|| "coordinator rejected the request".to_string()),
        ));
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_round_trip_has_no_private_key_field() {
        let req = ControlRequest::register(
            "super-secret-xyz",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "10.42.0.1",
            51820,
            Some("192.0.2.10:51820".into()),
        );
        let text = encode_toml(&req).unwrap();
        assert!(text.contains("kind = \"register\""));
        assert!(!text.contains("private"));
        let back: ControlRequest = decode_toml(&text).unwrap();
        assert_eq!(back.public_key, req.public_key);
        assert_eq!(back.listen_port, 51820);
        let debug = format!("{req:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("super-secret-xyz"));
    }

    #[test]
    fn frame_round_trip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, "kind = \"ok\"\n").unwrap();
        let body = read_frame(&mut buf.as_slice()).unwrap();
        assert_eq!(body, "kind = \"ok\"\n");
    }

    #[test]
    fn empty_frame_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u32.to_be_bytes());
        assert!(matches!(
            read_frame(&mut buf.as_slice()),
            Err(ProtocolError::FrameTooLarge(0))
        ));
    }
}
