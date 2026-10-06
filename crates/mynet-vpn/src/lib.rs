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
    apply_wireguard, parse_if_addrs, parse_latest_handshakes, parse_local_ipv4s, parse_src_ipv4,
    pick_advertise_ipv4, pick_lan_ipv4s, primary_ipv4, rank_lan_ipv4s, set_peer_endpoint_args,
    source_ipv4_toward, teardown_wireguard, upsert_wg_peer, upsert_wg_peer_args,
    wg_latest_handshakes, wg_set_args, IfAddr, WgError, WgPeer,
};
