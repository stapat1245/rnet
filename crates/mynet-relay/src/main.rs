//! Optional two-peer UDP relay. Forwards opaque datagrams only.
//!
//!   MYNET_LISTEN=0.0.0.0:9994 mynet-relay

use anyhow::{Context, Result};
use mynet_core::DEFAULT_RELAY_PORT;
use mynet_relay::bind_and_run;

fn main() -> Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    let listen = std::env::var("MYNET_LISTEN")
        .unwrap_or_else(|_| format!("0.0.0.0:{DEFAULT_RELAY_PORT}"));
    bind_and_run(&listen).with_context(|| format!("relay {listen}"))
}
