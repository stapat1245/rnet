//! mynet command-line entry point.
//!
//! Control-plane commands only. This binary does not create TUN devices,
//! send UDP, or carry VPN traffic.

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use mynet_core::{config_dir, identity_path_in, APP_NAME, CONFIG_DIR_ENV, VERSION};
use mynet_identity::Identity;

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
    /// Config directory (identity, later peers). Overrides MYNET_CONFIG_DIR.
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

fn cmd_init(dir: &std::path::Path, force: bool) -> Result<()> {
    let path = identity_path_in(dir);
    let identity = Identity::generate();
    identity.save_to(&path, force)?;
    tracing::info!(peer_id = %identity.peer_id(), path = %path.display(), "identity stored");
    println!("Identity created at {}", path.display());
    print_identity(&identity);
    Ok(())
}

fn cmd_identity(dir: &std::path::Path) -> Result<()> {
    let path = identity_path_in(dir);
    let identity = Identity::load_from(&path)?;
    print_identity(&identity);
    Ok(())
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
        assert!(help.contains(APP_NAME));
    }

    #[test]
    fn version_output_contains_package_version() {
        let text = format!("{APP_NAME} {VERSION}");
        assert!(text.contains("mynet"));
        assert!(text.contains("0.1.0"));
    }
}
