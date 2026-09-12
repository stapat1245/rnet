//! mynet command-line entry point.
//!
//! Control-plane commands only. This binary does not create TUN devices,
//! send UDP, or carry VPN traffic.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use mynet_core::{
    config_dir, identity_path_in, parse_endpoint, peers_path_in, Peer, PeerList, APP_NAME,
    CONFIG_DIR_ENV, VERSION,
};
use mynet_identity::{Identity, PublicKey};

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
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print the mynet version
    Version,
    /// Generate and store a local cryptographic identity
    Init {
        /// Overwrite an existing identity file
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
}

#[derive(Debug, Subcommand)]
enum PeerCommand {
    /// Trust a peer by public key (not by IP or hostname)
    Add {
        /// WireGuard-style base64 public key
        #[arg(long)]
        public_key: String,
        /// Overlay IPv4 address assigned to this peer
        #[arg(long)]
        ip: Ipv4Addr,
        /// Current UDP endpoint (discovery data, not identity)
        #[arg(long)]
        endpoint: Option<String>,
        /// Optional local nickname
        #[arg(long)]
        name: Option<String>,
    },
    /// List trusted peers
    List,
    /// Remove a trusted peer by name, peer ID, or public key
    Remove {
        /// Name, peer ID, or public key
        query: String,
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
    let path = identity_path_in(dir);
    let identity = Identity::load_from(&path)?;
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

fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    let dir = resolve_config_dir(cli.config_dir);
    std::env::set_var(CONFIG_DIR_ENV, &dir);

    match cli.command {
        Command::Version => println!("{APP_NAME} {VERSION}"),
        Command::Init { force } => cmd_init(&dir, force)?,
        Command::Identity => cmd_identity(&dir)?,
        Command::Peer { command } => match command {
            PeerCommand::Add {
                public_key,
                ip,
                endpoint,
                name,
            } => cmd_peer_add(&dir, public_key, ip, endpoint, name)?,
            PeerCommand::List => cmd_peer_list(&dir)?,
            PeerCommand::Remove { query } => cmd_peer_remove(&dir, query)?,
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn help_mentions_version() {
        let mut cmd = Cli::command();
        let help = cmd.render_long_help().to_string();
        assert!(help.contains("version"), "help should list the version subcommand");
        assert!(help.contains("init"));
        assert!(help.contains("identity"));
        assert!(help.contains("peer"));
        assert!(help.contains(APP_NAME));
    }

    #[test]
    fn version_output_contains_package_version() {
        let text = format!("{APP_NAME} {VERSION}");
        assert!(text.contains("mynet"));
        assert!(text.contains("0.1.0"));
    }
}
