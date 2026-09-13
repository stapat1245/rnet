//! Standalone hole-punch CLI. Not the VPN.
//!
//!   mynet-natpunch rendezvous [--bind 0.0.0.0:3478]
//!   mynet-natpunch peer --rendezvous HOST:3478 --id alice

use std::net::UdpSocket;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use mynet_core::DEFAULT_HOLEPUNCH_PORT;
use mynet_natpunch::{
    decode_kind, encode_hello, encode_peer, encode_punch, KIND_HELLO, KIND_PEER, KIND_PUNCH,
};

fn main() -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| "help".into());
    match cmd.as_str() {
        "rendezvous" => {
            let bind = args
                .find(|a| a != "--bind")
                .unwrap_or_else(|| format!("0.0.0.0:{DEFAULT_HOLEPUNCH_PORT}"));
            run_rendezvous(&bind)
        }
        "peer" => {
            let mut rendezvous = None;
            let mut id = "peer".to_string();
            while let Some(a) = args.next() {
                match a.as_str() {
                    "--rendezvous" => rendezvous = args.next(),
                    "--id" => id = args.next().unwrap_or(id),
                    _ => {}
                }
            }
            let rendezvous = rendezvous.context("pass --rendezvous HOST:PORT")?;
            run_peer(&rendezvous, &id)
        }
        _ => {
            eprintln!(
                "mynet-natpunch — standalone UDP hole punch (not the VPN)\n\
                 mynet-natpunch rendezvous [--bind 0.0.0.0:{DEFAULT_HOLEPUNCH_PORT}]\n\
                 mynet-natpunch peer --rendezvous HOST:{DEFAULT_HOLEPUNCH_PORT} --id alice"
            );
            Ok(())
        }
    }
}

fn run_rendezvous(bind: &str) -> Result<()> {
    let sock = UdpSocket::bind(bind).with_context(|| format!("bind {bind}"))?;
    tracing::info!(%bind, "hole-punch rendezvous (control experiment; no overlay packets)");
    let mut waiting: Option<(std::net::SocketAddr, String)> = None;
    let mut buf = [0u8; 512];
    loop {
        let (n, src) = sock.recv_from(&mut buf)?;
        let Ok((kind, rest)) = decode_kind(&buf[..n]) else {
            continue;
        };
        if kind != KIND_HELLO {
            continue;
        }
        let id = String::from_utf8_lossy(rest).into_owned();
        tracing::info!(%src, %id, "hello");
        if let Some((other, _)) = waiting.take() {
            sock.send_to(&encode_peer(src), other)?;
            sock.send_to(&encode_peer(other), src)?;
        } else {
            waiting = Some((src, id));
        }
    }
}

fn run_peer(rendezvous: &str, id: &str) -> Result<()> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_read_timeout(Some(Duration::from_secs(8)))?;
    sock.send_to(&encode_hello(id), rendezvous)?;
    let mut buf = [0u8; 512];
    let (n, _) = sock.recv_from(&mut buf).context("waiting for peer info")?;
    let (kind, rest) = decode_kind(&buf[..n])?;
    if kind != KIND_PEER {
        bail!("expected PEER frame");
    }
    let peer = std::str::from_utf8(rest)?.trim();
    tracing::info!(%peer, "punching");
    sock.send_to(&encode_punch(id), peer)?;
    let (n, src) = sock.recv_from(&mut buf).context("waiting for PUNCH")?;
    let (kind, _) = decode_kind(&buf[..n])?;
    if kind != KIND_PUNCH {
        bail!("expected PUNCH, got {kind}");
    }
    println!("hole punch ok from {src}");
    Ok(())
}
