//! rnet/mynet CLI: `rnet start` plus `rnet connect <secret>`, and lab helpers.
//!
//! `tun-test` and `connect --plain` are learning paths. Encrypted traffic
//! uses kernel WireGuard.

mod coord;

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command as ProcCommand;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use mynet_core::{
    config_dir, identity_path_in, local_path_in, parse_endpoint, peers_path_in, session_path_in,
    split_host_port, Invite, LocalConfig, LocalError, Peer, PeerList, PeerState, SessionEvent,
    SessionTable, APP_NAME, CONFIG_DIR_ENV, COORDINATOR_SYNC_SECS, DEFAULT_COORDINATOR_PORT,
    DEFAULT_INTERFACE, DEFAULT_LISTEN_PORT, DEFAULT_RELAY_PORT, HANDSHAKE_TIMEOUT_SECS,
    INVITE_SYNC_SECS, VERSION,
};
use mynet_identity::{Identity, IdentityError, PublicKey};
use mynet_transport::run_plain_loop;
use mynet_vpn::{
    apply_wireguard, parse_ipv4, primary_ipv4, teardown_wireguard, upsert_wg_peer,
    wg_latest_handshakes, TunDevice, TunError, WgPeer,
};
use serde::Deserialize;

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

fn install_stop_handler() {
    unsafe {
        libc::signal(libc::SIGINT, on_signal as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as libc::sighandler_t);
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "rnet",
    version,
    about = "rnet start, then rnet connect <secret>",
    long_about = "rnet (mynet) is a learning-focused peer-to-peer VPN for Linux.\n\n\
Typical use: `rnet start` on one machine, then `rnet connect <secret>` on the other.\n\
Peers authenticate with public keys. Overlay traffic is kernel WireGuard.\n\
The coordinator inside `start` is control plane only and is never the VPN data path."
)]
struct Cli {
    /// Config directory (identity, peers). Overrides MYNET_CONFIG_DIR.
    #[arg(long, global = true, env = "MYNET_CONFIG_DIR")]
    config_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    /// Print the mynet version
    Version,
    /// Generate and store a local cryptographic identity
    Init {
        #[arg(long)]
        force: bool,
    },
    /// Show this node's public identity (never prints the private key)
    Identity,
    /// Manage the local trusted-peer list
    Peer {
        #[command(subcommand)]
        command: PeerCommand,
    },
    /// Create a TUN, assign IPv4, optionally read packets (needs root)
    TunTest {
        #[arg(long, default_value = DEFAULT_INTERFACE)]
        interface: String,
        /// Overlay IPv4 (must be in 10.42.0.0/24)
        #[arg(long)]
        ip: Ipv4Addr,
        /// Seconds to run (0 = configure, print, exit)
        #[arg(long, default_value_t = 0)]
        duration: u64,
    },
    /// Print a secret and keep the VPN up until Ctrl-C
    Start {
        #[arg(long, hide = true, default_value_t = DEFAULT_LISTEN_PORT)]
        listen_port: u16,
        #[arg(long, hide = true, default_value = DEFAULT_INTERFACE)]
        interface: String,
    },
    /// Join with the secret from `rnet start`
    Connect {
        /// Secret printed by `rnet start`
        secret: Option<String>,
        #[arg(long, hide = true)]
        ip: Option<Ipv4Addr>,
        #[arg(long, hide = true, default_value_t = DEFAULT_LISTEN_PORT)]
        listen_port: u16,
        #[arg(long, hide = true, default_value = DEFAULT_INTERFACE)]
        interface: String,
        #[arg(long, hide = true)]
        plain: bool,
        #[arg(long, hide = true)]
        relay: Option<String>,
    },
    /// Tear down the overlay interface
    Disconnect {
        #[arg(long, default_value = DEFAULT_INTERFACE)]
        interface: String,
    },
    /// Print a pasteable peer record for out-of-band exchange
    Export {
        #[arg(long)]
        ip: Option<Ipv4Addr>,
        /// This node's currently reachable UDP endpoint (discovery, not identity)
        #[arg(long)]
        endpoint: Option<String>,
    },
    /// Register with a coordinator and trust advertised members (join token = membership)
    Join {
        /// Coordinator host:port (VPS public IP and published TCP port)
        #[arg(long)]
        coordinator: String,
        /// Shared join token (same value as MYNET_JOIN_TOKEN on the VPS)
        #[arg(long, env = "MYNET_JOIN_TOKEN")]
        token: String,
        #[arg(long)]
        ip: Option<Ipv4Addr>,
        /// Ask the coordinator for the next free overlay IP instead of passing --ip
        #[arg(long)]
        allocate: bool,
        #[arg(long, default_value_t = DEFAULT_LISTEN_PORT)]
        listen_port: u16,
        #[arg(long, default_value = DEFAULT_INTERFACE)]
        interface: String,
        /// Optional self-declared WireGuard UDP endpoint (host:port)
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long)]
        network: Option<String>,
    },
    /// Re-register, refresh endpoints, and pick up new members from the coordinator
    Sync {
        #[arg(long)]
        endpoint: Option<String>,
    },
    /// Show identity, overlay, coordinator host (never the join token)
    Status,
}

#[derive(Debug, Subcommand)]
enum PeerCommand {
    Add {
        #[arg(long)]
        public_key: String,
        #[arg(long)]
        ip: Ipv4Addr,
        #[arg(long)]
        endpoint: Option<String>,
        #[arg(long)]
        name: Option<String>,
    },
    List,
    Remove {
        query: String,
    },
    /// Import a record produced by `mynet export`
    Import {
        /// Path to an exported TOML snippet
        file: PathBuf,
        #[arg(long)]
        name: Option<String>,
    },
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

fn resolve_config_dir(explicit: Option<PathBuf>) -> PathBuf {
    match explicit {
        Some(dir) => dir,
        None => config_dir(),
    }
}

fn print_identity(identity: &Identity) {
    println!("Peer ID: {}", identity.peer_id());
    println!("Public Key: {}", identity.public_key());
}

fn invoked_as() -> String {
    std::env::args_os()
        .next()
        .as_ref()
        .and_then(|p| Path::new(p).file_name())
        .and_then(|s| s.to_str())
        .unwrap_or("rnet")
        .to_string()
}

fn euid_is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn require_net_admin(action: &str) -> Result<()> {
    if euid_is_root() {
        return Ok(());
    }
    let bin = invoked_as();
    bail!(
        "{action} needs root to create the WireGuard interface.\n  sudo {bin} {action}\n\
         (sudo keeps your user config; do not run `{bin} init` as root)"
    );
}

fn random_token() -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| anyhow::anyhow!("random token: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn ensure_identity(dir: &Path) -> Result<Identity> {
    let path = identity_path_in(dir);
    match Identity::load_from(&path) {
        Ok(id) => Ok(id),
        Err(IdentityError::NotFound { .. }) => {
            let identity = Identity::generate();
            identity.save_to(&path, false)?;
            tracing::info!(peer_id = %identity.peer_id(), path = %path.display(), "identity stored");
            println!("Identity created at {}", path.display());
            print_identity(&identity);
            Ok(identity)
        }
        Err(e) => Err(e.into()),
    }
}

#[derive(Debug, Deserialize)]
struct DiscoveryFile {
    coordinator: String,
    #[serde(default)]
    relay: Option<String>,
}

fn relay_for_coordinator(coordinator: &str) -> Result<String> {
    let (host, _) = split_host_port(coordinator)?;
    Ok(format!("{host}:{DEFAULT_RELAY_PORT}"))
}

fn load_discovery(dir: &Path) -> Result<(String, String)> {
    if let Ok(v) = std::env::var("RNET_DISCOVERY").or_else(|_| std::env::var("MYNET_DISCOVERY")) {
        let v = v.trim().to_string();
        if !v.is_empty() {
            split_host_port(&v)?;
            let relay = relay_for_coordinator(&v)?;
            return Ok((v, relay));
        }
    }
    let path = dir.join("discovery.toml");
    if path.exists() {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("read {}", path.display()))?;
        let parsed: DiscoveryFile = toml::from_str(&text).context("discovery.toml is malformed")?;
        split_host_port(&parsed.coordinator)?;
        let relay = match parsed.relay {
            Some(r) => {
                split_host_port(&r)?;
                r
            }
            None => relay_for_coordinator(&parsed.coordinator)?,
        };
        return Ok((parsed.coordinator, relay));
    }
    if let Ok(local) = LocalConfig::load_from(&local_path_in(dir)) {
        if let Some(c) = local.coordinator {
            let relay = local
                .relay
                .unwrap_or_else(|| relay_for_coordinator(&c).unwrap_or_else(|_| c.clone()));
            return Ok((c, relay));
        }
    }
    let bin = invoked_as();
    bail!(
        "{bin} start needs a public discovery server (your VPS/VM on the internet).\n\
         Create {} with:\n\n\
         coordinator = \"VPS_PUBLIC_IP:{DEFAULT_COORDINATOR_PORT}\"\n\
         relay = \"VPS_PUBLIC_IP:{DEFAULT_RELAY_PORT}\"\n\n\
         On the VPS: docker compose up -d\n\
         Or set RNET_DISCOVERY=VPS_PUBLIC_IP:{DEFAULT_COORDINATOR_PORT}",
        path.display()
    );
}

fn tcp_reachable(coordinator: &str, timeout: Duration) -> bool {
    let Ok((host, port)) = split_host_port(coordinator) else {
        return false;
    };
    let Ok(mut addrs) = (host, port).to_socket_addrs() else {
        return false;
    };
    let Some(addr) = addrs.find(|a| a.is_ipv4()) else {
        return false;
    };
    std::net::TcpStream::connect_timeout(&addr, timeout).is_ok()
}

fn pick_coordinator(candidates: &[String]) -> Result<String> {
    let timeout = Duration::from_secs(5);
    for c in candidates {
        tracing::info!(coordinator = %c, "trying discovery server");
        if tcp_reachable(c, timeout) {
            return Ok(c.clone());
        }
    }
    bail!(
        "could not reach the discovery server (tried {}). Is the VPS up and is TCP 9993 open?",
        candidates.join(", ")
    )
}

fn cmd_start(dir: &Path, listen_port: u16, interface: String) -> Result<()> {
    require_net_admin("start")?;
    let (coordinator, relay) = load_discovery(dir)?;
    let identity = ensure_identity(dir)?;
    let token = random_token()?;
    tracing::info!(coordinator = %coordinator, "registering with public discovery server");
    let ip = coord::allocate_ip(&coordinator, &token, &identity.public_key().to_base64())?;
    tracing::info!(overlay = %ip, "assigned overlay IP");
    reset_session_membership(dir)?;
    let report = coord::join(
        dir,
        coordinator.clone(),
        token.clone(),
        ip,
        listen_port,
        interface.clone(),
        None,
        Some("rnet".into()),
    )?;
    coord::print_report(&report);

    let invite = Invite::new(
        vec![coordinator],
        token,
        listen_port,
        Some(relay.clone()),
    )?;
    let secret = invite.encode();
    let bin = invoked_as();
    let banner = format!(
        "\nsecret    {secret}\noverlay   {ip}\niface     {interface}\n\nOn the other computer (anywhere on the internet), whenever you are ready:\n  {bin} connect {secret}\n\nThis side waits until Ctrl-C.\n"
    );

    cmd_connect(
        dir,
        Some(ip),
        listen_port,
        interface,
        false,
        Some(relay),
        INVITE_SYNC_SECS,
        Some(banner),
    )
}

fn cmd_connect_invite(
    dir: &Path,
    secret: String,
    listen_port: u16,
    interface: String,
) -> Result<()> {
    let _ = listen_port;
    let invite = Invite::decode(&secret)?;
    require_net_admin("connect")?;
    let identity = ensure_identity(dir)?;
    let coordinator = pick_coordinator(&invite.coordinators)?;
    tracing::info!(coordinator = %coordinator, "reached discovery server");
    let ip = coord::allocate_ip(
        &coordinator,
        &invite.token,
        &identity.public_key().to_base64(),
    )?;
    tracing::info!(overlay = %ip, "assigned overlay IP");
    println!("overlay   {ip}");
    reset_session_membership(dir)?;
    let report = coord::join(
        dir,
        coordinator.clone(),
        invite.token.clone(),
        ip,
        invite.listen_port,
        interface.clone(),
        None,
        Some("rnet".into()),
    )?;
    coord::print_report(&report);
    let relay = invite
        .relay
        .clone()
        .or_else(|| relay_for_coordinator(&coordinator).ok());
    cmd_connect(
        dir,
        Some(ip),
        invite.listen_port,
        interface,
        false,
        relay,
        INVITE_SYNC_SECS,
        None,
    )
}

fn cmd_init(dir: &Path, force: bool) -> Result<()> {
    let path = identity_path_in(dir);
    let identity = Identity::generate();
    identity.save_to(&path, force)?;
    tracing::info!(peer_id = %identity.peer_id(), path = %path.display(), "identity stored");
    println!("Identity created at {}", path.display());
    print_identity(&identity);
    Ok(())
}

fn cmd_identity(dir: &Path) -> Result<()> {
    let identity = Identity::load_from(&identity_path_in(dir))?;
    print_identity(&identity);
    Ok(())
}

fn cmd_peer_add(
    dir: &Path,
    public_key: String,
    ip: Ipv4Addr,
    endpoint: Option<String>,
    name: Option<String>,
) -> Result<()> {
    let public_key = PublicKey::from_base64(&public_key)?;
    let endpoint = match endpoint {
        Some(s) => Some(parse_endpoint(&s)?),
        None => None,
    };
    let peer = Peer::new(public_key, ip, endpoint, name)?;
    add_peer(dir, peer)
}

fn add_peer(dir: &Path, peer: Peer) -> Result<()> {
    if let Ok(local) = Identity::load_from(&identity_path_in(dir)) {
        if local.public_key() == peer.public_key {
            bail!("refusing to add this node's own public key");
        }
    }
    let path = peers_path_in(dir);
    let mut list = PeerList::load_from(&path)?;
    list.add(peer.clone())?;
    list.save_to(&path)?;
    tracing::info!(peer_id = %peer.id, ip = %peer.virtual_ip, "trusted peer added");
    println!("Trusted peer {}", peer.display_name());
    print_peer(&peer);
    Ok(())
}

fn cmd_peer_list(dir: &Path) -> Result<()> {
    let list = PeerList::load_from(&peers_path_in(dir))?;
    if list.is_empty() {
        println!("No trusted peers.");
        return Ok(());
    }
    for (i, peer) in list.peers().iter().enumerate() {
        if i > 0 {
            println!();
        }
        print_peer(peer);
    }
    Ok(())
}

fn cmd_peer_remove(dir: &Path, query: String) -> Result<()> {
    let path = peers_path_in(dir);
    let mut list = PeerList::load_from(&path)?;
    let removed = list.remove(&query)?;
    list.save_to(&path)?;
    tracing::info!(peer_id = %removed.id, "trusted peer removed");
    println!("Removed {}", removed.display_name());
    Ok(())
}

fn cmd_peer_import(dir: &Path, file: PathBuf, name: Option<String>) -> Result<()> {
    let text = std::fs::read_to_string(&file)
        .with_context(|| format!("read {}", file.display()))?;
    let rec: ExchangeRecord = toml::from_str(&text).context("invalid export TOML")?;
    let endpoint = rec.endpoint.map(|s| parse_endpoint(&s)).transpose()?;
    let peer = Peer::new(
        PublicKey::from_base64(&rec.public_key)?,
        rec.virtual_ip.parse().context("virtual_ip")?,
        endpoint,
        name.or(rec.name),
    )?;
    add_peer(dir, peer)
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct ExchangeRecord {
    public_key: String,
    #[serde(default)]
    peer_id: Option<String>,
    virtual_ip: String,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

fn cmd_export(dir: &Path, ip: Option<Ipv4Addr>, endpoint: Option<String>) -> Result<()> {
    let identity = Identity::load_from(&identity_path_in(dir))?;
    let ip = match ip {
        Some(ip) => ip,
        None => LocalConfig::load_from(&local_path_in(dir))
            .context("pass --ip or save local settings via connect")?
            .virtual_ip,
    };
    let rec = ExchangeRecord {
        public_key: identity.public_key().to_base64(),
        peer_id: Some(identity.peer_id().to_hex()),
        virtual_ip: ip.to_string(),
        endpoint,
        name: None,
    };
    println!("# mynet peer exchange v1");
    println!("# Identity is public_key. endpoint is discovery data.");
    print!("{}", toml::to_string_pretty(&rec).context("serialize export")?);
    Ok(())
}

fn print_peer(peer: &Peer) {
    println!("{}", peer.display_name());
    println!("  Peer ID:    {}", peer.id);
    println!("  Public Key: {}", peer.public_key);
    println!("  IP:         {}", peer.virtual_ip);
    match peer.endpoint {
        Some(ep) => println!("  Endpoint:   {ep}"),
        None => println!("  Endpoint:   (none)"),
    }
    println!("  State:      {}", peer.state.as_str());
}

fn persist_overlay(
    dir: &Path,
    ip: Ipv4Addr,
    listen_port: u16,
    interface: String,
) -> Result<LocalConfig> {
    let path = local_path_in(dir);
    let existing = match LocalConfig::load_from(&path) {
        Ok(c) => Some(c),
        Err(LocalError::NotFound { .. }) => None,
        Err(e) => return Err(e.into()),
    };
    let mut cfg = LocalConfig::new(ip, listen_port, interface)?;
    if let Some(old) = existing {
        cfg.coordinator = old.coordinator;
        cfg.network = old.network;
        cfg.join_token = old.join_token;
        cfg.relay = old.relay;
    }
    cfg.save_to(&path)?;
    Ok(cfg)
}

fn cmd_tun_test(interface: String, ip: Ipv4Addr, duration: u64) -> Result<()> {
    let _cfg = LocalConfig::new(ip, DEFAULT_LISTEN_PORT, interface.clone())?;
    let mut tun = match TunDevice::open(&interface) {
        Ok(t) => t,
        Err(TunError::Permission) => {
            bail!("need CAP_NET_ADMIN or root to create a TUN interface (try: sudo mynet tun-test)");
        }
        Err(e) => return Err(e.into()),
    };
    tun.configure_ipv4(ip, 24)?;
    println!("TUN {} {}", tun.name(), ip);
    let _ = dump_ip(&["addr", "show", "dev", tun.name()]);
    let _ = dump_ip(&["link", "show", "dev", tun.name()]);
    let _ = dump_ip(&["route", "show", "dev", tun.name()]);
    if duration == 0 {
        println!("(duration=0: exiting; interface is removed when the process exits)");
        return Ok(());
    }
    install_stop_handler();
    let deadline = std::time::Instant::now() + Duration::from_secs(duration);
    let mut buf = [0u8; 2048];
    println!("reading packets until Ctrl-C or {duration}s …");
    tun_nonblock(&tun)?;
    while !STOP.load(Ordering::Relaxed) && std::time::Instant::now() < deadline {
        match tun.read(&mut buf) {
            Ok(0) => {}
            Ok(n) => {
                if let Ok(info) = parse_ipv4(&buf[..n]) {
                    println!(
                        "pkt proto={} src={} dst={} bytes={}",
                        info.proto, info.src, info.dst, n
                    );
                } else {
                    println!("pkt non-ipv4 bytes={n}");
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn tun_nonblock(tun: &TunDevice) -> Result<()> {
    let fd = tun.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn dump_ip(args: &[&str]) -> Result<()> {
    let bin = if Path::new("/usr/sbin/ip").exists() {
        "/usr/sbin/ip"
    } else {
        "ip"
    };
    let out = ProcCommand::new(bin).args(args).output()?;
    print!("{}", String::from_utf8_lossy(&out.stdout));
    Ok(())
}

fn cmd_connect(
    dir: &Path,
    ip: Option<Ipv4Addr>,
    listen_port: u16,
    interface: String,
    plain: bool,
    relay: Option<String>,
    sync_secs: u64,
    after_up: Option<String>,
) -> Result<()> {
    let identity = Identity::load_from(&identity_path_in(dir))?;
    let ip = match ip {
        Some(ip) => ip,
        None => LocalConfig::load_from(&local_path_in(dir))?.virtual_ip,
    };
    let mut cfg = persist_overlay(dir, ip, listen_port, interface.clone())?;
    if let Some(relay) = relay {
        split_host_port(&relay)?;
        cfg.relay = Some(relay);
        cfg.save_to(&local_path_in(dir))?;
    }
    if cfg.coordinator.is_some() {
        match coord::register_and_apply(
            dir,
            &identity,
            &cfg,
            true,
            None,
        ) {
            Ok(report) => coord::print_report(&report),
            Err(e) => tracing::warn!(
                error = %e,
                "coordinator unreachable; connecting with last known peers"
            ),
        }
    }
    let list = PeerList::load_from(&peers_path_in(dir))?;

    if plain {
        println!("WARNING: --plain forwards overlay IPv4 as unencrypted UDP.");
        println!("This is a learning path. It is NOT the VPN. Use `rnet connect` for WireGuard.");
        cmd_connect_plain(&cfg, &list)?;
    } else {
        cmd_connect_wireguard(dir, &identity, &cfg, &list, sync_secs, after_up)?;
    }
    Ok(())
}

fn cmd_connect_plain(cfg: &LocalConfig, list: &PeerList) -> Result<()> {
    let routes: HashMap<Ipv4Addr, SocketAddr> = list.udp_routes().into_iter().collect();
    if routes.is_empty() {
        tracing::warn!("no trusted peers have endpoints; outbound overlay packets will be dropped");
    }
    let mut tun = TunDevice::open(&cfg.interface)?;
    tun.configure_ipv4(cfg.virtual_ip, 24)?;
    let sock = UdpSocket::bind(("0.0.0.0", cfg.listen_port))
        .with_context(|| format!("bind UDP :{}", cfg.listen_port))?;
    println!(
        "plain overlay {} {}  UDP :{}",
        tun.name(),
        cfg.virtual_ip,
        cfg.listen_port
    );
    install_stop_handler();
    run_plain_loop(&mut tun, &sock, cfg.virtual_ip, &routes, &STOP)?;
    Ok(())
}

fn cmd_connect_wireguard(
    dir: &Path,
    identity: &Identity,
    cfg: &LocalConfig,
    list: &PeerList,
    sync_secs: u64,
    after_up: Option<String>,
) -> Result<()> {
    let relay_addr = match &cfg.relay {
        Some(s) => Some(resolve_host_port(s)?),
        None => None,
    };
    let peers: Vec<WgPeer> = list
        .peers()
        .iter()
        .map(|p| WgPeer {
            public_key_base64: p.public_key.to_base64(),
            endpoint: p.endpoint,
            allowed_ip: p.virtual_ip,
        })
        .collect();
    if peers.is_empty() {
        tracing::warn!("no trusted peers; interface will still come up");
    }
    apply_wireguard(
        &cfg.interface,
        identity.private_key_bytes(),
        cfg.listen_port,
        cfg.virtual_ip,
        24,
        &peers,
    )?;
    println!(
        "WireGuard {} {}  UDP :{}",
        cfg.interface, cfg.virtual_ip, cfg.listen_port
    );
    if let Some(msg) = after_up {
        println!("{msg}");
    }
    if let Some(c) = &cfg.coordinator {
        println!("coordinator {c} (control plane only; overlay UDP does not go there)");
    }
    if let Some(r) = &cfg.relay {
        println!("relay {r} (opaque UDP fallback for two peers; not the coordinator)");
    }
    let _ = dump_ip(&["addr", "show", "dev", &cfg.interface]);
    let _ = dump_ip(&["route", "show", "dev", &cfg.interface]);
    let _ = dump_wg(&cfg.interface);

    let session_path = session_path_in(dir);
    let mut sessions = SessionTable::new();
    let mut connecting_since: HashMap<String, Instant> = HashMap::new();
    for p in list.peers() {
        begin_peer_session(
            &mut sessions,
            &mut connecting_since,
            &p.public_key.to_base64(),
            p.endpoint,
            relay_addr,
        );
    }
    let _ = sessions.save_to(&session_path);

    println!(
        "Press Ctrl-C to disconnect (or run `{} disconnect`).",
        invoked_as()
    );
    install_stop_handler();
    let mut last_sync = Instant::now();
    let mut last_src = primary_ipv4();
    let handshake_timeout = Duration::from_secs(HANDSHAKE_TIMEOUT_SECS);
    while !STOP.load(Ordering::Relaxed) {
        if let Ok(handshakes) = wg_latest_handshakes(&cfg.interface) {
            for (pk, ts) in handshakes {
                if ts > 0 {
                    let before = sessions.get(&pk).map(|r| r.state);
                    let _ = sessions.apply(&pk, SessionEvent::HandshakeOk, None);
                    if before == Some(PeerState::Connecting) {
                        tracing::info!(peer = %pk, "peer handshake ok");
                        connecting_since.remove(&pk);
                    }
                }
            }
        }
        failover_connecting_peers(
            &mut sessions,
            &mut connecting_since,
            dir,
            &cfg.interface,
            relay_addr,
            handshake_timeout,
        )?;
        let src_changed = {
            let now = primary_ipv4();
            let changed = now.is_some() && now != last_src;
            if changed {
                tracing::info!(src = ?now, "primary IPv4 changed; re-publishing endpoints");
                last_src = now;
            }
            changed
        };
        if cfg.coordinator.is_some()
            && (src_changed || last_sync.elapsed() >= Duration::from_secs(sync_secs.max(1)))
        {
            last_sync = Instant::now();
            match coord::register_and_apply(dir, identity, cfg, true, None) {
                Ok(report) => {
                    if report.added > 0 || report.updated > 0 {
                        tracing::info!(
                            added = report.added,
                            updated = report.updated,
                            "applying coordinator endpoint updates"
                        );
                        // Always take new peers. Do not rewrite endpoints for
                        // peers already on the pair relay.
                        apply_live_peers(dir, &cfg.interface, &sessions)?;
                        let list = PeerList::load_from(&peers_path_in(dir))?;
                        for p in list.peers() {
                            begin_peer_session(
                                &mut sessions,
                                &mut connecting_since,
                                &p.public_key.to_base64(),
                                p.endpoint,
                                relay_addr,
                            );
                        }
                    }
                }
                Err(e) => tracing::warn!(
                    error = %e,
                    "coordinator unreachable; WireGuard session unchanged"
                ),
            }
        }
        let _ = sessions.save_to(&session_path);
        thread::sleep(Duration::from_millis(250));
    }
    let _ = SessionTable::remove_file(&session_path);
    teardown_wireguard(&cfg.interface)?;
    println!("disconnected");
    Ok(())
}

fn reset_session_membership(dir: &Path) -> Result<()> {
    PeerList::new()
        .save_to(&peers_path_in(dir))
        .context("reset peers.toml for a new session")?;
    let _ = SessionTable::remove_file(&session_path_in(dir));
    Ok(())
}

fn begin_peer_session(
    sessions: &mut SessionTable,
    connecting_since: &mut HashMap<String, Instant>,
    pk: &str,
    endpoint: Option<SocketAddr>,
    relay_addr: Option<SocketAddr>,
) {
    if sessions.get(pk).is_some() {
        return;
    }
    let _ = sessions.apply(pk, SessionEvent::Start, None);
    if endpoint.is_some() {
        let _ = sessions.apply(pk, SessionEvent::EndpointKnown, endpoint);
        connecting_since.insert(pk.to_string(), Instant::now());
    } else if relay_addr.is_some() {
        let _ = sessions.apply(pk, SessionEvent::RelayReady, relay_addr);
    } else {
        let _ = sessions.apply(pk, SessionEvent::NoEndpoint, None);
    }
}

fn failover_connecting_peers(
    sessions: &mut SessionTable,
    connecting_since: &mut HashMap<String, Instant>,
    dir: &Path,
    iface: &str,
    relay_addr: Option<SocketAddr>,
    timeout: Duration,
) -> Result<()> {
    let due: Vec<String> = sessions
        .rows()
        .filter(|r| r.state == PeerState::Connecting)
        .filter(|r| {
            connecting_since
                .get(&r.public_key)
                .map(|started| started.elapsed() >= timeout)
                .unwrap_or(false)
        })
        .map(|r| r.public_key.clone())
        .collect();
    if due.is_empty() {
        return Ok(());
    }
    let list = PeerList::load_from(&peers_path_in(dir))?;
    if let Some(relay) = relay_addr {
        tracing::warn!(
            %relay,
            n = due.len(),
            "direct handshake timed out; failing over to pair relay"
        );
        for pk in due {
            let allowed_ip = match list
                .peers()
                .iter()
                .find(|p| p.public_key.to_base64() == pk)
            {
                Some(p) => p.virtual_ip,
                None => continue,
            };
            let _ = sessions.apply(&pk, SessionEvent::RelayReady, Some(relay));
            connecting_since.remove(&pk);
            let wg = WgPeer {
                public_key_base64: pk.clone(),
                endpoint: Some(relay),
                allowed_ip,
            };
            if let Err(e) = upsert_wg_peer(iface, &wg) {
                tracing::warn!(error = %e, "relay endpoint update failed");
                let _ = sessions.apply(&pk, SessionEvent::RelayFail, None);
            }
        }
    } else {
        for pk in due {
            let _ = sessions.apply(&pk, SessionEvent::HandshakeTimeout, None);
            connecting_since.remove(&pk);
        }
    }
    Ok(())
}

fn resolve_host_port(s: &str) -> Result<SocketAddr> {
    let (host, port) = mynet_core::split_host_port(s)?;
    use std::net::ToSocketAddrs;
    (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolve {s}"))?
        .find(|a| a.is_ipv4())
        .with_context(|| format!("no IPv4 address for {s}"))
}

fn apply_live_peers(dir: &Path, iface: &str, sessions: &SessionTable) -> Result<()> {
    let list = PeerList::load_from(&peers_path_in(dir))?;
    for p in list.peers() {
        let pk = p.public_key.to_base64();
        if sessions.get(&pk).map(|r| r.state) == Some(PeerState::Relaying) {
            continue;
        }
        let peer = WgPeer {
            public_key_base64: pk,
            endpoint: p.endpoint,
            allowed_ip: p.virtual_ip,
        };
        if let Err(e) = upsert_wg_peer(iface, &peer) {
            tracing::warn!(error = %e, public_key = %p.public_key, "wg peer update failed");
        }
    }
    Ok(())
}

fn dump_wg(iface: &str) -> Result<()> {
    let bin = if Path::new("/usr/bin/wg").exists() {
        "/usr/bin/wg"
    } else {
        "wg"
    };
    let out = ProcCommand::new(bin).args(["show", iface]).output()?;
    print!("{}", String::from_utf8_lossy(&out.stdout));
    Ok(())
}

fn cmd_disconnect(dir: &Path, interface: String) -> Result<()> {
    let _ = SessionTable::remove_file(&session_path_in(dir));
    teardown_wireguard(&interface)?;
    // TUN devices vanish when the creating process exits; leftover names:
    let _ = ProcCommand::new("ip")
        .args(["link", "del", "dev", &interface])
        .output();
    println!("removed {interface} (if it existed)");
    Ok(())
}

fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    let dir = resolve_config_dir(cli.config_dir);
    std::env::set_var(CONFIG_DIR_ENV, &dir);

    match cli.command {
        CliCommand::Version => println!("{APP_NAME} {VERSION}"),
        CliCommand::Init { force } => cmd_init(&dir, force)?,
        CliCommand::Identity => cmd_identity(&dir)?,
        CliCommand::Peer { command } => match command {
            PeerCommand::Add {
                public_key,
                ip,
                endpoint,
                name,
            } => cmd_peer_add(&dir, public_key, ip, endpoint, name)?,
            PeerCommand::List => cmd_peer_list(&dir)?,
            PeerCommand::Remove { query } => cmd_peer_remove(&dir, query)?,
            PeerCommand::Import { file, name } => cmd_peer_import(&dir, file, name)?,
        },
        CliCommand::TunTest {
            interface,
            ip,
            duration,
        } => cmd_tun_test(interface, ip, duration)?,
        CliCommand::Start {
            listen_port,
            interface,
        } => cmd_start(&dir, listen_port, interface)?,
        CliCommand::Connect {
            secret,
            ip,
            listen_port,
            interface,
            plain,
            relay,
        } => {
            if let Some(secret) = secret {
                if ip.is_some() || plain || relay.is_some() {
                    bail!("`connect <secret>` does not take extra flags");
                }
                cmd_connect_invite(&dir, secret, listen_port, interface)?;
            } else {
                cmd_connect(
                    &dir,
                    ip,
                    listen_port,
                    interface,
                    plain,
                    relay,
                    COORDINATOR_SYNC_SECS,
                    None,
                )?;
            }
        }
        CliCommand::Disconnect { interface } => cmd_disconnect(&dir, interface)?,
        CliCommand::Export { ip, endpoint } => cmd_export(&dir, ip, endpoint)?,
        CliCommand::Join {
            coordinator,
            token,
            ip,
            allocate,
            listen_port,
            interface,
            endpoint,
            network,
        } => {
            let ip = if allocate {
                if ip.is_some() {
                    bail!("pass --ip or --allocate, not both");
                }
                let identity = Identity::load_from(&identity_path_in(&dir))?;
                coord::allocate_ip(&coordinator, &token, &identity.public_key().to_base64())?
            } else {
                ip.context("pass --ip <10.42.0.N> or --allocate")?
            };
            println!("Overlay IP: {ip}");
            let report = coord::join(
                &dir,
                coordinator,
                token,
                ip,
                listen_port,
                interface,
                endpoint,
                network,
            )?;
            coord::print_report(&report);
        }
        CliCommand::Sync { endpoint } => {
            let report = coord::sync(&dir, endpoint)?;
            coord::print_report(&report);
        }
        CliCommand::Status => cmd_status(&dir)?,
    }
    Ok(())
}

fn cmd_status(dir: &Path) -> Result<()> {
    let identity = Identity::load_from(&identity_path_in(dir))?;
    print_identity(&identity);
    match LocalConfig::load_from(&local_path_in(dir)) {
        Ok(cfg) => {
            println!("Overlay IP:  {}", cfg.virtual_ip);
            println!("Listen UDP:  {}", cfg.listen_port);
            println!("Interface:   {}", cfg.interface);
            match cfg.coordinator {
                Some(c) => println!("Coordinator: {c} (TCP control plane)"),
                None => println!(
                    "Coordinator: (none; default port {DEFAULT_COORDINATOR_PORT})"
                ),
            }
            if let Some(net) = cfg.network {
                println!("Network:     {net}");
            }
            match cfg.relay {
                Some(r) => println!("Relay:       {r} (two-peer UDP fallback)"),
                None => println!("Relay:       (none)"),
            }
            if cfg.join_token.is_some() {
                println!("Join token:  [set, not printed]");
            }
        }
        Err(LocalError::NotFound { .. }) => {
            println!("Overlay:     (not configured; pass --ip on join/connect)");
        }
        Err(e) => return Err(e.into()),
    }
    let list = PeerList::load_from(&peers_path_in(dir))?;
    let sessions = SessionTable::load_from(&session_path_in(dir)).unwrap_or_default();
    println!("Trusted:     {} peer(s)", list.peers().len());
    for peer in list.peers() {
        let pk = peer.public_key.to_base64();
        let state = sessions
            .get(&pk)
            .map(|r| r.state)
            .unwrap_or(PeerState::Disconnected);
        println!(
            "  {}  {}  {}  {}",
            peer.display_name(),
            peer.virtual_ip,
            peer.endpoint
                .map(|e| e.to_string())
                .unwrap_or_else(|| "(no endpoint)".into()),
            state
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn help_mentions_core_commands() {
        let mut cmd = Cli::command();
        let help = cmd.render_long_help().to_string();
        for needle in [
            "version", "init", "identity", "peer", "tun-test", "connect", "disconnect", "export",
            "join", "sync", "status", "start",
        ] {
            assert!(help.contains(needle), "help missing {needle}");
        }
        assert!(help.contains(APP_NAME));
    }
}
