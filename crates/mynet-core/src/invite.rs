//! Copy-paste invite from `rnet start` for `rnet connect <secret>`.
//!
//! The secret is not a WireGuard key. It carries the public discovery
//! server, a session token, and optional relay so the joiner needs no extra flags.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::{split_host_port, DEFAULT_LISTEN_PORT};

pub const INVITE_PREFIX: &str = "rnet1.";

/// How often `rnet start` / invite `connect` re-registers so a new peer
/// is picked up quickly.
pub const INVITE_SYNC_SECS: u64 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invite {
    /// Discovery server `host:port` values (usually one public VPS).
    pub coordinators: Vec<String>,
    pub token: String,
    pub listen_port: u16,
    /// Optional pair-UDP relay `host:port` (same VPS, different port).
    pub relay: Option<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InviteError {
    #[error("not an invite from `rnet start` (expected {INVITE_PREFIX}…)")]
    BadPrefix,
    #[error("invite is malformed")]
    Malformed,
    #[error("invite coordinator must be host:port")]
    BadCoordinator,
    #[error("invite listen port must not be 0")]
    BadListenPort,
}

impl Invite {
    pub fn new(
        coordinators: Vec<String>,
        token: String,
        listen_port: u16,
        relay: Option<String>,
    ) -> Result<Self, InviteError> {
        if coordinators.is_empty() || token.is_empty() {
            return Err(InviteError::Malformed);
        }
        if listen_port == 0 {
            return Err(InviteError::BadListenPort);
        }
        for c in &coordinators {
            split_host_port(c).map_err(|_| InviteError::BadCoordinator)?;
        }
        if let Some(r) = &relay {
            split_host_port(r).map_err(|_| InviteError::BadCoordinator)?;
        }
        Ok(Invite {
            coordinators,
            token,
            listen_port,
            relay,
        })
    }

    pub fn encode(&self) -> String {
        let list = self.coordinators.join(",");
        let relay = self.relay.clone().unwrap_or_default();
        let payload = format!("3|{list}|{}|{}|{relay}", self.token, self.listen_port);
        format!("{INVITE_PREFIX}{}", URL_SAFE_NO_PAD.encode(payload.as_bytes()))
    }

    pub fn decode(secret: &str) -> Result<Self, InviteError> {
        let secret = secret.trim();
        let rest = secret
            .strip_prefix(INVITE_PREFIX)
            .ok_or(InviteError::BadPrefix)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(rest.as_bytes())
            .map_err(|_| InviteError::Malformed)?;
        let text = String::from_utf8(bytes).map_err(|_| InviteError::Malformed)?;
        let parts: Vec<&str> = text.split('|').collect();
        if parts.len() < 4 {
            return Err(InviteError::Malformed);
        }
        let ver = parts[0];
        let coordinator_field = parts[1];
        let token = parts[2].to_string();
        let listen_port: u16 = parts[3].parse().map_err(|_| InviteError::Malformed)?;
        let relay = match ver {
            "1" | "2" => None,
            "3" => {
                if parts.len() < 5 {
                    return Err(InviteError::Malformed);
                }
                let r = parts[4].trim();
                if r.is_empty() {
                    None
                } else {
                    Some(r.to_string())
                }
            }
            _ => return Err(InviteError::Malformed),
        };
        let coordinators: Vec<String> = match ver {
            "1" => vec![coordinator_field.to_string()],
            "2" | "3" => coordinator_field
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect(),
            _ => return Err(InviteError::Malformed),
        };
        Invite::new(coordinators, token, listen_port, relay)
    }

    pub fn candidate_ips(&self) -> Vec<std::net::Ipv4Addr> {
        self.coordinators
            .iter()
            .filter_map(|c| split_host_port(c).ok())
            .filter_map(|(h, _)| h.parse().ok())
            .collect()
    }
}

impl Default for Invite {
    fn default() -> Self {
        Invite {
            coordinators: vec!["127.0.0.1:9993".into()],
            token: "unset".into(),
            listen_port: DEFAULT_LISTEN_PORT,
            relay: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_with_relay() {
        let inv = Invite::new(
            vec!["203.0.113.10:9993".into()],
            "aabbccddeeff00112233445566778899".into(),
            51820,
            Some("203.0.113.10:9994".into()),
        )
        .unwrap();
        let secret = inv.encode();
        assert!(secret.starts_with(INVITE_PREFIX));
        assert!(!secret.contains('+'));
        assert!(!secret.contains('/'));
        assert_eq!(Invite::decode(&secret).unwrap(), inv);
        assert_eq!(Invite::decode(&format!("  {secret}  ")).unwrap(), inv);
    }

    #[test]
    fn v1_secret_still_decodes() {
        let payload = "1|192.168.56.1:9993|aabbccddeeff0011|51820";
        let secret = format!(
            "{INVITE_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(payload.as_bytes())
        );
        let inv = Invite::decode(&secret).unwrap();
        assert_eq!(inv.coordinators, vec!["192.168.56.1:9993".to_string()]);
        assert_eq!(inv.token, "aabbccddeeff0011");
        assert_eq!(inv.listen_port, 51820);
        assert!(inv.relay.is_none());
    }

    #[test]
    fn garbage_rejected() {
        assert_eq!(Invite::decode("nope"), Err(InviteError::BadPrefix));
        assert_eq!(Invite::decode("rnet1.???"), Err(InviteError::Malformed));
    }

    #[test]
    fn coordinator_must_have_port() {
        assert!(Invite::new(
            vec!["192.168.56.1".into()],
            "tok".into(),
            51820,
            None
        )
        .is_err());
    }
}
