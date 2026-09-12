//! UDP transport for overlay packets.
//!
//! Phase 4 uses an explicit `MYN1` datagram around a raw IPv4 packet. That
//! path is **not encrypted**. Phase 5 replaces it with kernel WireGuard.

mod frame;
mod forward;

pub use frame::{decode, encode, FrameError, MAGIC};
pub use forward::{forward_outbound, run_plain_loop, ForwardError};
