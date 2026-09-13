//! Linux TUN device (virtual networking) and kernel WireGuard control
//! (encryption). This crate does not invent cryptography.

mod packet;
mod tun;
mod wireguard;

pub use packet::{parse_ipv4, Ipv4Info, PacketError};
pub use tun::{
    install_overlay_route, overlay_route_del_args, overlay_route_replace_args, remove_overlay_route,
    tun_available, TunDevice, TunError,
};
pub use wireguard::{
    apply_wireguard, parse_latest_handshakes, parse_src_ipv4, primary_ipv4, set_peer_endpoint_args,
    teardown_wireguard, upsert_wg_peer, upsert_wg_peer_args, wg_latest_handshakes, wg_set_args,
    WgError, WgPeer,
};
