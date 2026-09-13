//! mynet coordination server.
//!
//! Control plane only: registration, presence, public-key lookup, endpoints.
//! Overlay / WireGuard packets must never be sent to this process.

use std::net::TcpListener;

use anyhow::{Context, Result};
use mynet_coordinator::{serve, CoordinatorConfig};
use mynet_core::DEFAULT_COORDINATOR_PORT;

fn main() -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    let listen = std::env::var("MYNET_LISTEN")
        .unwrap_or_else(|_| format!("0.0.0.0:{DEFAULT_COORDINATOR_PORT}"));
    let listener = TcpListener::bind(&listen)
        .with_context(|| format!("bind {listen}"))?;
    serve(listener, CoordinatorConfig::from_env()).context("coordinator serve")
}
