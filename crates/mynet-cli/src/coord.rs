//! Coordinator client: register, discover, apply advertised members.
//!
//! Joining with a token is the trust decision for membership. Overlay traffic
//! is still authenticated by kernel WireGuard using those public keys.

use std::net::Ipv4Addr;
use std::path::Path;

use anyhow::{bail, Context, Result};
use mynet_core::{parse_endpoint, ApplyKind, LocalConfig, PeerError, PeerList};
use mynet_identity::{Identity, PublicKey};
use mynet_protocol::{rpc, AdvertisedPeer, ControlRequest};

pub struct SyncReport {
    pub added: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub rejected: Vec<String>,
}

pub fn allocate_ip(coordinator: &str, token: &str, public_key: &str) -> Result<Ipv4Addr> {
    let resp = rpc(coordinator, &ControlRequest::allocate(token, public_key))?;
    let ip = resp
        .assigned_ip
        .context("coordinator did not assign an overlay IP")?;
    ip.parse().context("allocated virtual_ip")
}

pub fn join(
    dir: &Path,
    coordinator: String,
    token: String,
    ip: Ipv4Addr,
    listen_port: u16,
    interface: String,
    endpoint: Option<String>,
    network: Option<String>,
) -> Result<SyncReport> {
    let identity = Identity::load_from(&mynet_core::identity_path_in(dir))
        .context("run `mynet init` before join")?;
    let mut local = match LocalConfig::load_from(&mynet_core::local_path_in(dir)) {
        Ok(cfg) => cfg,
        Err(mynet_core::LocalError::NotFound { .. }) => {
            LocalConfig::new(ip, listen_port, interface.clone())?
        }
        Err(e) => return Err(e.into()),
    };
    let mut overlay = LocalConfig::new(ip, listen_port, interface)?;
    overlay.coordinator = Some(coordinator);
    overlay.network = network.or(local.network.take());
    overlay.join_token = Some(token);
    overlay.relay = local.relay.take();
    overlay.save_to(&mynet_core::local_path_in(dir))?;
    register_and_apply(dir, &identity, &overlay, true, endpoint)
}

pub fn sync(dir: &Path, endpoint: Option<String>) -> Result<SyncReport> {
    let identity = Identity::load_from(&mynet_core::identity_path_in(dir))
        .context("run `mynet init` before sync")?;
    let local = LocalConfig::load_from(&mynet_core::local_path_in(dir))
        .context("run `mynet join` first (no local.toml)")?;
    if local.coordinator.is_none() {
        bail!("no coordinator configured; run `mynet join --coordinator HOST:PORT`");
    }
    register_and_apply(dir, &identity, &local, true, endpoint)
}

pub fn register_and_apply(
    dir: &Path,
    identity: &Identity,
    local: &LocalConfig,
    allow_new: bool,
    advertised_endpoint: Option<String>,
) -> Result<SyncReport> {
    let coordinator = local
        .coordinator
        .as_deref()
        .context("no coordinator in local.toml")?;
    let token = local.join_token.clone().unwrap_or_default();
    let req = ControlRequest::register(
        token,
        identity.public_key().to_base64(),
        local.virtual_ip.to_string(),
        local.listen_port,
        advertised_endpoint,
    );
    tracing::info!(coordinator, "registering with coordinator");
    let resp = rpc(coordinator, &req)?;
    apply_advertised(dir, identity, &resp.peers, allow_new)
}

fn apply_advertised(
    dir: &Path,
    identity: &Identity,
    peers: &[AdvertisedPeer],
    allow_new: bool,
) -> Result<SyncReport> {
    let path = mynet_core::peers_path_in(dir);
    let mut list = PeerList::load_from(&path)?;
    let mut report = SyncReport {
        added: 0,
        updated: 0,
        unchanged: 0,
        rejected: Vec::new(),
    };
    let self_pk = identity.public_key();
    for adv in peers {
        let public_key = match PublicKey::from_base64(&adv.public_key) {
            Ok(pk) => pk,
            Err(_) => {
                report.rejected.push(format!("invalid public key {}", adv.public_key));
                continue;
            }
        };
        if public_key == self_pk {
            report.unchanged += 1;
            continue;
        }
        let virtual_ip: Ipv4Addr = match adv.virtual_ip.parse() {
            Ok(ip) => ip,
            Err(_) => {
                report.rejected.push(format!("invalid virtual_ip {}", adv.virtual_ip));
                continue;
            }
        };
        let endpoint = match &adv.endpoint {
            Some(s) => match parse_endpoint(s) {
                Ok(ep) => Some(ep),
                Err(_) => {
                    report.rejected.push(format!("invalid endpoint {s}"));
                    continue;
                }
            },
            None => None,
        };
        match list.apply_discovery(public_key, virtual_ip, endpoint, allow_new, None) {
            Ok(ApplyKind::Added) => {
                tracing::info!(public_key = %public_key, ip = %virtual_ip, "trusted peer added from coordinator");
                report.added += 1;
            }
            Ok(ApplyKind::EndpointUpdated) => {
                tracing::info!(public_key = %public_key, "endpoint updated from coordinator");
                report.updated += 1;
            }
            Ok(ApplyKind::Unchanged) => report.unchanged += 1,
            Err(PeerError::UnknownPublicKey) => {
                report.rejected.push(format!("{} is not a trusted peer", public_key));
            }
            Err(PeerError::VirtualIpMismatch { trusted, advertised }) => {
                report.rejected.push(format!(
                    "{} advertised overlay {advertised} but trusted mapping is {trusted}",
                    public_key
                ));
            }
            Err(e) => report.rejected.push(e.to_string()),
        }
    }
    list.save_to(&path)?;
    Ok(report)
}

pub fn print_report(report: &SyncReport) {
    println!(
        "coordinator sync: added {}  updated {}  unchanged {}",
        report.added, report.updated, report.unchanged
    );
    for msg in &report.rejected {
        println!("  rejected: {msg}");
    }
}
