//! Linux TUN device (virtual networking) and kernel WireGuard control
//! (encryption). This crate does not invent cryptography.

mod packet;
mod tun;
mod wireguard;

pub use packet::{parse_ipv4, Ipv4Info, PacketError};
pub use tun::{tun_available, TunDevice, TunError};
pub use wireguard::{apply_wireguard, teardown_wireguard, wg_set_args, WgError, WgPeer};
