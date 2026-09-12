//! mynet CLI: control plane plus Linux data-plane helpers.
//!
//! `tun-test` and `connect --plain` are learning paths. Encrypted traffic
//! uses kernel WireGuard (`mynet connect` without `--plain`).

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command as ProcCommand;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use mynet_core::{
    config_dir, identity_path_in, local_path_in, parse_endpoint, peers_path_in, LocalConfig, Peer,
    PeerList, APP_NAME, CONFIG_DIR_ENV, DEFAULT_INTERFACE, DEFAULT_LISTEN_PORT, VERSION,
};
use mynet_identity::{Identity, PublicKey};
use mynet_transport::run_plain_loop;
use mynet_vpn::{
    apply_wireguard, parse_ipv4, teardown_wireguard, TunDevice, TunError, WgPeer,
};

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
    name = APP_NAME,
    version,
    about = "A small Linux P2P VPN built from first principles",
    long_about = "mynet is a learning-focused peer-to-peer VPN for Linux.\n\n\
Peers authenticate with public keys, get virtual IPv4 addresses, and send \
encrypted traffic directly over UDP when possible. A coordination server, \
if used later, is for discovery only and is never the VPN data path."
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
    /// Bring up the overlay (kernel WireGuard, or --plain UDP)
    Connect {
        #[arg(long)]
        ip: Option<Ipv4Addr>,
        #[arg(long, default_value_t = DEFAULT_LISTEN_PORT)]
        listen_port: u16,
        #[arg(long, default_value = DEFAULT_INTERFACE)]
        interface: String,
        /// INSECURE: TUN + plaintext UDP instead of WireGuard
        #[arg(long)]
        plain: bool,
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

fn persist_local(dir: &Path, ip: Ipv4Addr, listen_port: u16, interface: String) -> Result<LocalConfig> {
    let cfg = LocalConfig::new(ip, listen_port, interface)?;
    cfg.save_to(&local_path_in(dir))?;
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
) -> Result<()> {
    let identity = Identity::load_from(&identity_path_in(dir))?;
    let ip = match ip {
        Some(ip) => ip,
        None => LocalConfig::load_from(&local_path_in(dir))?.virtual_ip,
    };
    let cfg = persist_local(dir, ip, listen_port, interface.clone())?;
    let list = PeerList::load_from(&peers_path_in(dir))?;

    if plain {
        println!("WARNING: --plain forwards overlay IPv4 as unencrypted UDP.");
        println!("This is a learning path. It is NOT the VPN. Use `mynet connect` for WireGuard.");
        cmd_connect_plain(&cfg, &list)?;
    } else {
        cmd_connect_wireguard(&identity, &cfg, &list)?;
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

fn cmd_connect_wireguard(identity: &Identity, cfg: &LocalConfig, list: &PeerList) -> Result<()> {
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
    let _ = dump_ip(&["addr", "show", "dev", &cfg.interface]);
    let _ = dump_wg(&cfg.interface);
    println!("Press Ctrl-C to disconnect (or run `mynet disconnect`).");
    install_stop_handler();
    while !STOP.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(250));
    }
    teardown_wireguard(&cfg.interface)?;
    println!("disconnected");
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

fn cmd_disconnect(interface: String) -> Result<()> {
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
        CliCommand::Connect {
            ip,
            listen_port,
            interface,
            plain,
        } => cmd_connect(&dir, ip, listen_port, interface, plain)?,
        CliCommand::Disconnect { interface } => cmd_disconnect(interface)?,
        CliCommand::Export { ip, endpoint } => cmd_export(&dir, ip, endpoint)?,
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
        ] {
            assert!(help.contains(needle), "help missing {needle}");
        }
        assert!(help.contains(APP_NAME));
    }
}
