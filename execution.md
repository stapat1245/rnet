# How to run mynet

This is the operator guide. It answers **what runs where**, **where the VPS IP and port go**, and **how to start the coordinator in Docker**.

mynet is a peer-to-peer VPN. Encrypted overlay traffic is WireGuard UDP, preferably **laptop to laptop**. The VPS is a **discovery server** plus an optional **pair UDP relay** for when both laptops sit behind NAT. `rnet start` / `rnet connect SECRET` use that VPS; the secret is the membership.

```text
  laptop A  -------- WireGuard UDP :51820 (direct if NAT allows) --------  laptop B
       \                               |                                 /
        \                              | UDP :9994 relay (two peers)    /
         \                             v                               /
          \---- TCP :9993 discovery ---- VPS (coordinator + relay) ----/
```

| Role | Machine | Process | Listens | Carries VPN payload? |
| --- | --- | --- | --- | --- |
| Coordinator | VPS | `mynet-coordinator` (Docker) | TCP **9993** | **No** |
| Pair relay | VPS | `mynet-relay` (Docker, default) | UDP **9994** | Opaque WG datagrams only (two peers) |
| Node | Each laptop/PC | `rnet` | UDP **51820** (WireGuard) | **Yes**, to the other node or via the pair relay |
| Identity | Each laptop | `identity.toml` | — | Private key never leaves the machine |

On each laptop that will run `rnet start`, put the VPS public IP in `~/.config/mynet/discovery.toml`. The person who only runs `rnet connect SECRET` does not need that file; the secret includes the discovery address.

Default overlay: `10.42.0.0/24`. `rnet start` takes `.1` in a new session room; `rnet connect` is allocated `.2`.

---

## Where to put the VPS IP and port

You will have a public IP and a TCP port for the coordinator. They go in **two places**, for two different jobs.

### 1. VPS — published TCP port (Docker)

On the VPS, copy [`.env.example`](.env.example) to `.env` in the **repository root** (same directory as `docker-compose.yml`):

```bash
cp .env.example .env
```

Edit `.env`:

```bash
# TCP port Docker publishes on the VPS. Change this if 9993 is taken
# or if you want 8443 / 443. The container still listens on 9993 internally.
MYNET_COORD_PORT=9993

# Shared secret. Laptops must present the same string.
MYNET_JOIN_TOKEN=replace-with-a-long-random-string

MYNET_NETWORK=office
```

You do **not** put the VPS public IP in `.env`. Docker binds `0.0.0.0:MYNET_COORD_PORT` on the VPS. The IP is whatever the VPS already has.

Firewall on the VPS: allow **inbound TCP** on `MYNET_COORD_PORT`. Do not open UDP 51820 on the VPS unless you are also running a mynet node there (you usually are not).

### 2. Each laptop — coordinator address

On every laptop, the VPS public IP and the **published** port go on `mynet join`:

```bash
mynet join --coordinator VPS_PUBLIC_IP:9993 --token 'the-same-token' --ip 10.42.0.1
```

If you set `MYNET_COORD_PORT=8443` in the VPS `.env`, laptops must use `:8443`, not `:9993`.

That command writes `$XDG_CONFIG_HOME/mynet/local.toml` (or `$MYNET_CONFIG_DIR/local.toml`):

```toml
coordinator = "VPS_PUBLIC_IP:9993"
join_token = "the-same-token"
virtual_ip = "10.42.0.1"
listen_port = 51820
```

That is the persistent place the IP:port live on a node. `mynet sync` and `mynet connect` read it from there. You can also pass the token as `MYNET_JOIN_TOKEN` in the laptop environment instead of `--token`.

Do **not** put the VPS address in `peers.toml`. Peer endpoints are **WireGuard UDP** addresses of other laptops, learned from the coordinator or from `mynet export`.

---

## What to run on the VPS

Only the coordinator. Clone this repo (or copy it), then:

```bash
# on the VPS, from the repository root
cp .env.example .env
# edit MYNET_JOIN_TOKEN (and MYNET_COORD_PORT if you want)

docker compose up -d --build
docker compose logs -f coordinator
```

Check it is listening:

```bash
ss -lnt | grep 9993
# or: docker compose ps
```

Useful environment variables (already set by Compose):

| Variable | Meaning |
| --- | --- |
| `MYNET_LISTEN` | Bind address inside the container (`0.0.0.0:9993`) |
| `MYNET_JOIN_TOKEN` | Membership secret. Empty = anyone can register (lab only) |
| `MYNET_NETWORK` | Informational label |
| `MYNET_STATE_PATH` | Persisted member list (`/var/lib/mynet/state.toml`) |

Without Docker, from a checkout with Rust:

```bash
export MYNET_LISTEN=0.0.0.0:9993
export MYNET_JOIN_TOKEN='the-same-token'
export MYNET_STATE_PATH=/var/lib/mynet/state.toml
cargo run --release -p mynet-coordinator
```

The coordinator binary is `mynet-coordinator`, not `mynet`. It never creates a TUN or a WireGuard interface.

---

## What to run on each local computer

Linux with `wireguard` + `wireguard-tools`, and this tree built:

```bash
cargo build --release -p mynet-cli
sudo install -m 755 target/release/mynet /usr/local/bin/mynet
```

Pick a unique overlay IP per machine. Example: Alice `10.42.0.1`, Bob `10.42.0.2`.

### First time

```bash
mynet init
mynet identity          # public key only; private key is never printed
```

If the laptop has a **stable public IP or a UDP port-forward for 51820**, tell the coordinator that WireGuard endpoint (recommended when you are not on the same LAN):

```bash
mynet join \
  --coordinator VPS_PUBLIC_IP:9993 \
  --token 'the-same-token' \
  --ip 10.42.0.1 \
  --endpoint LAPTOP_PUBLIC_IP:51820
```

If you omit `--endpoint`, the coordinator records `observed_tcp_ip:listen_port`. That is the laptop's address as the VPS sees the TCP join, plus UDP 51820. That is often right for a VPS-facing public IP, and often **wrong** behind consumer NAT (Phase 10). Same-LAN testing can omit `--endpoint`.

Then:

```bash
mynet status            # shows coordinator host, not the token
mynet peer list         # other members the coordinator advertised
sudo mynet connect      # kernel WireGuard; needs CAP_NET_ADMIN
# uses SUDO_USER's ~/.config/mynet (not /root). Until rebuilt:
# sudo MYNET_CONFIG_DIR="$HOME/.config/mynet" mynet connect
```

`mynet connect` re-registers with the coordinator if `local.toml` has a coordinator, then brings up `mynet0`. While connected it refreshes endpoints about every 30 seconds. If the VPS dies, existing WireGuard sessions keep using the last known endpoints.

```bash
sudo mynet disconnect
```

### Later sessions

```bash
mynet sync              # refresh members/endpoints without bringing up the VPN
sudo mynet connect
```

### Optional: no VPS

Skip Docker entirely. Exchange keys by hand:

```bash
mynet export --ip 10.42.0.1 --endpoint HOST:51820 > /tmp/alice.toml
# copy the file to the other machine
mynet peer import /tmp/alice.toml --name alice
sudo mynet connect
```

---

## Ports cheat sheet

| Port | Protocol | Where | Purpose |
| --- | --- | --- | --- |
| `MYNET_COORD_PORT` (default 9993) | TCP | VPS, inbound | Join / sync / discovery |
| `MYNET_RELAY_PORT` (default 9994) | UDP | VPS, inbound, optional | Two-peer opaque relay |
| 3478 | UDP | experiment host, optional | `mynet-natpunch` rendezvous (not WG) |
| 51820 | UDP | Each laptop, inbound if possible | WireGuard data plane |

Do not send WireGuard packets to port 9993. Do not point `peers.toml` endpoints at the VPS unless that VPS is also a mynet **node**.

Laptop firewall: allow UDP 51820 from the other peers (or rely on NAT hole punching later; that is not implemented yet).

---

## Docker notes

- Image is built from [`deploy/coordinator/Dockerfile`](deploy/coordinator/Dockerfile).
- Compose file is [`docker-compose.yml`](docker-compose.yml) at the repo root.
- The container is **unprivileged**. It does not need `/dev/net/tun`.
- State is a Docker volume (`coordinator-state`). Recreating the container keeps membership if the volume remains.
- Changing the host port: set `MYNET_COORD_PORT` in `.env`. Laptops must use that new port.

To use a host port of 8443:

```bash
# VPS .env
MYNET_COORD_PORT=8443
```

```bash
# laptop
mynet join --coordinator VPS_PUBLIC_IP:8443 --token '…' --ip 10.42.0.1
# or let the coordinator pick the next free overlay IP:
mynet join --coordinator VPS_PUBLIC_IP:8443 --token '…' --allocate
```

---

## Optional pair relay (two laptops)

If direct WireGuard UDP cannot complete a handshake (typical behind two NATs), run a **second** process on the VPS. It is not the coordinator and it does not decrypt overlay packets. It copies UDP between exactly two sources.

```bash
# on the VPS, from the repository root
docker compose up -d --build
```

Firewall: allow **inbound UDP** on `MYNET_RELAY_PORT` (default **9994**). Put that port in `.env` as `MYNET_RELAY_PORT`. Laptops use the VPS public IP:

```bash
sudo mynet connect --relay VPS_PUBLIC_IP:9994
```

If the direct handshake is still failing after 15 seconds, mynet points both WireGuard peers at the relay. Two nodes only. A third laptop cannot share this relay.

Without Docker:

```bash
export MYNET_LISTEN=0.0.0.0:9994
cargo run --release -p mynet-relay
```

---

## Standalone hole-punch experiment (not the VPN)

This does not carry overlay traffic and does not use kernel WireGuard. It is the Phase 10 lab tool:

```bash
# machine that both peers can send UDP to (can be the VPS, a different port)
cargo run -p mynet-natpunch -- rendezvous --bind 0.0.0.0:3478

# each laptop
cargo run -p mynet-natpunch -- peer --rendezvous VPS_PUBLIC_IP:3478 --id alice
```

Same LAN / same host should print `hole punch ok`. Symmetric NAT is expected to fail; that is recorded in `notes.md`, not hidden.

---

## Threat model (short)

- **Identity** is the X25519 public key. Overlay IP and UDP endpoint are not identity.
- **Trust** is `peers.toml`, filled by `mynet peer add` / `peer import` / `mynet join` (join token = membership decision).
- Kernel WireGuard authenticates live traffic. Unknown keys cannot decrypt overlay packets.
- A stolen join token lets someone register as a new member. Rotate the token and rebuild membership if that happens.
- Coordinator compromise leaks public keys and endpoints, not private keys and not overlay plaintext.
- `--plain` is an unencrypted learning path. Do not use it as a VPN.

See [`notes.md`](notes.md) for the longer write-up.
