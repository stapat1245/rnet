# rnet

A small Linux VPN. One machine starts a network and prints a secret; the other joins with that secret. Both get overlay IPs on `10.42.0.0/24` (`mynet0`). Traffic is kernel WireGuard.

Works across different home networks. A VPS is used only for discovery and, if NAT blocks direct UDP, a two-peer relay.

## Architecture

```text
Person A  <-- WireGuard UDP -->  Person B
    |                               |
    +------ TCP 9993 (discovery) ---+
    +------ UDP 9994 (relay) -------+
                    |
                   VPS
```

- **Identity** is an X25519 public key (WireGuard-compatible), not an IP.
- **Coordinator** (TCP 9993) assigns overlay IPs and tells each side the other’s public key and endpoint. It never sees VPN packets.
- **Data path** is kernel WireGuard. Direct UDP is tried first; after 15s with no handshake, both sides fail over to the VPS relay (UDP 9994).

## Install

**Linux**, `rustc` 1.75+, `wireguard-tools`, and root (`sudo`) on each laptop. Open **TCP 9993** and **UDP 9994** on the VPS firewall.



### Users

```bash
curl -fsSL https://rnet.stapat.xyz/install.sh | bash
```

### VPS (once default server is running :()

```bash
git clone https://github.com/stapat1245/rnet.git
cd rnet
cp .env.example .env
docker compose up -d
```
## Use

Person A:

```bash
sudo rnet start
```

Leave it running. It prints a secret and `10.42.0.1`.

Person B, any time while A is still up:

```bash
sudo rnet connect rnet1.…
```

Gets `10.42.0.2`. Then `ping 10.42.0.1`. Ctrl-C (or `sudo rnet disconnect`) stops the network.

Config lives in `~/.config/mynet` even under `sudo`.
