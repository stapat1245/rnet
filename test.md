# Alice / Bob / VPS tests

Hands-on checklist for two Linux machines (**Alice**, **Bob**) and one **VPS**. Fill in the blanks once, then run the tests in order.

This is not `cargo test`. That suite is `RUSTFLAGS="-D warnings" cargo test --workspace` on a single box. These tests are the two-host and VPS paths that unit tests cannot claim.

How to run the binaries in general: [`execution.md`](execution.md).

---

## Fill in once

```bash
# VPS public IPv4
VPS_IP=203.0.113.10

# Must match MYNET_JOIN_TOKEN in the VPS .env
TOKEN='replace-with-a-long-random-string'

# Published coordinator TCP port (MYNET_COORD_PORT)
COORD_PORT=9993

# Published pair-relay UDP port (MYNET_RELAY_PORT); only for Test 8
RELAY_PORT=9994

# Optional: this laptop's public IPv4 or port-forwarded WAN address
# Leave empty on a LAN test
ALICE_WAN=
BOB_WAN=
```

| Role | Overlay IP | WireGuard UDP |
| --- | --- | --- |
| Alice | `10.42.0.1` | `51820` |
| Bob | `10.42.0.2` | `51820` |
| VPS coordinator | — | — (TCP `$COORD_PORT` only) |
| VPS relay (optional) | — | UDP `$RELAY_PORT` |

VPN packets must go **Alice ↔ Bob** (or Alice ↔ relay ↔ Bob). They must **not** go to coordinator TCP `$COORD_PORT`.

---

## Laptop + Kali VM (same NAT)

This is the usual home-lab layout: **Alice = host Linux**, **Bob = Kali VM** (VMware/VirtualBox NAT or host-only). Both share one public IP. Do **not** put that WAN address in `--endpoint`. WireGuard must use the **VM-network / LAN IPs** so packets stay on the virtual switch.

### VirtualBox: Internal Network or NAT (`10.0.2.15`)

`10.0.2.15/24` is VirtualBox **NAT**, not a LAN the host sits on. From the guest, the host is usually `10.0.2.2`. From the host, `ping 10.0.2.15` almost always fails. **Internal Network** is even stricter: only VMs on that name see each other; the host has no iface there.

Alice (host) and Bob (Kali) cannot run a VPN until they have **mutual IPv4 ping**. Add a second NIC:

1. VM settings → Network → **Adapter 2** → enable → **Host-only Adapter** (`vboxnet0`). Keep Adapter 1 as NAT if you want Kali to reach the VPS (`172.197.216.135:9993`).
2. Start Kali, then `ip -4 addr`. You want a new address such as `192.168.56.101`.
3. On the host: `ip -4 addr show vboxnet0` (often `192.168.56.1`).
4. `ping` host↔Kali on those `192.168.56.x` addresses. Only then join/connect.
5. Kali needs `wireguard-tools`. For **internet** (two different networks), both machines need the VPS reachable on TCP 9993 and UDP 9994, and the starter needs `~/.config/mynet/discovery.toml`:

```bash
coordinator = "172.197.216.135:9993"
relay = "172.197.216.135:9994"
```

**Starter (any network)**

```bash
sudo rnet start
```

**Joiner (any other network)**

```bash
sudo rnet connect rnet1.…
```

Leave both running until Ctrl-C. Overlay ping `10.42.0.1` ↔ `10.42.0.2`. Direct WireGuard is tried first; NAT pairs fall back to the VPS relay.

The older `mynet join --coordinator …` flow still works. `sudo` must keep the user's config, not `/root/.config/mynet`.

Bridged adapter on the home Wi-Fi also works (both get `192.168.1.x` / `192.168.0.x`). Do not use `curl ifconfig.me` (`103.85.126.24`) as `--endpoint` for this pair.

1. Call the host IP `ALICE_LAN` and the VM IP `BOB_LAN` (the host-only or bridged addresses, not `10.0.2.15`). Overlay stays `10.42.0.1` / `10.42.0.2` (must not be the same prefix as `ALICE_LAN`).
2. `mynet join --endpoint ALICE_LAN:51820` on the host, `BOB_LAN:51820` on Kali.
3. If `mynet join` to the VPS times out, skip the coordinator and use **Test 3 (manual export/import)** with those LAN endpoints. You can still prove Alice↔Bob ping. Fix TCP 9993 later (next section).

---

## Join times out (`connection timed out`)

`docker ps` showing `0.0.0.0:9993->9993/tcp` only proves the container listens **on the VPS**. A timeout from your laptop means something in front of Docker is dropping TCP 9993 (UFW, iptables, or the cloud **security group** / firewall).

On the **VPS**:

```bash
ss -lnt | grep 9993
sudo ufw allow 9993/tcp
sudo ufw status
# if ufw is inactive, check iptables / nft:
sudo iptables -L INPUT -n | head
# cloud panels (Oracle, AWS, GCP, DO, Hetzner): add inbound TCP 9993 from 0.0.0.0/0 or from your home IP
```

From the **laptop** (not from the VPS):

```bash
nc -vz 172.197.216.135 9993
# or:
timeout 5 bash -c 'echo >/dev/tcp/172.197.216.135/9993' && echo open || echo blocked
```

**Pass:** `succeeded` / `open` in about a second. Then `mynet join --coordinator 172.197.216.135:9993` will work.  
**Fail:** still `timed out` — do not keep retrying join. Open the cloud firewall, or test Alice↔Bob with manual import on the VM LAN (Test 3) until 9993 works.

`VPS_PUBLIC_IP` in the join command is a placeholder. Use the real IPv4 (`172.197.216.135`), never the string `VPS_PUBLIC_IP`.

---

## 0. VPS — coordinator

On the VPS, from the repository root:

```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-v2
# or: docker compose plugin already present

git clone <this-repo> mynet
cd mynet
cp .env.example .env
```

Edit `.env`:

```bash
MYNET_COORD_PORT=9993
MYNET_JOIN_TOKEN='replace-with-a-long-random-string'
MYNET_NETWORK=office
MYNET_RELAY_PORT=9994
```

Firewall (UFW example):

```bash
sudo ufw allow 9993/tcp comment 'mynet coordinator'
# only if you will run Test 8:
sudo ufw allow 9994/udp comment 'mynet pair relay'
sudo ufw status
```

Start the coordinator (**no TUN, no WireGuard, no extra capabilities**):

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f coordinator
```

In another shell:

```bash
ss -lnt | grep 9993
# expect: 0.0.0.0:9993 or *:9993 LISTEN
```

**Pass:** container `mynet-coordinator` is up, TCP `$COORD_PORT` is listening.  
**Fail:** build error, port already taken, firewall still closed.

Do **not** start the relay yet. Test 4 is direct P2P. Test 8 is the relay.

Without Docker:

```bash
export MYNET_LISTEN=0.0.0.0:9993
export MYNET_JOIN_TOKEN='replace-with-a-long-random-string'
export MYNET_STATE_PATH=/var/lib/mynet/state.toml
mkdir -p /var/lib/mynet
cargo run --release -p mynet-coordinator
```

---

## 1. Alice and Bob — packages and binary

On **both** laptops:

```bash
sudo apt-get update
sudo apt-get install -y build-essential pkg-config wireguard wireguard-tools
rustc --version          # 1.75+ ; this repo is pinned for 1.75
modprobe wireguard || true
wg --version
ls -l /dev/net/tun
```

Build and install `mynet` (from the repo):

```bash
cargo build --release -p mynet-cli
sudo install -m 755 target/release/mynet /usr/local/bin/mynet
mynet version
```

**Pass:** `mynet version` prints `mynet 0.1.0`, `wg` exists, `/dev/net/tun` exists.  
**Fail:** missing `CAP_NET_ADMIN` will show up later on `connect`, not here.

Isolated config dirs (recommended so you do not mix with a previous run):

```bash
# Alice
export MYNET_CONFIG_DIR="$HOME/mynet-alice"
mkdir -p "$MYNET_CONFIG_DIR"
chmod 700 "$MYNET_CONFIG_DIR"

# Bob
export MYNET_CONFIG_DIR="$HOME/mynet-bob"
mkdir -p "$MYNET_CONFIG_DIR"
chmod 700 "$MYNET_CONFIG_DIR"
```

Keep that `export` in every Alice/Bob shell below, or pass `--config-dir` on every command.

---

## 2. Identity (no network)

**Alice**

```bash
mynet init
mynet identity
```

**Bob**

```bash
mynet init
mynet identity
```

**Pass:** each prints a Peer ID and a Public Key; they differ; the word `private` does not appear.  
**Fail:** second `mynet init` without `--force` must exit 1.

```bash
mynet init           # must fail
mynet init --force   # only if you intend to throw the old key away
```

---

## 3. Manual exchange (no VPS)

Use this if the coordinator is down, or to prove Phase 6 by itself.

On Alice, pick an endpoint Bob can send UDP to (LAN IP or WAN:51820):

```bash
# Alice
ip -4 addr
mynet export --ip 10.42.0.1 --endpoint ALICE_LAN_OR_WAN:51820 > /tmp/alice.toml
cat /tmp/alice.toml    # must contain public_key, must not contain private_key
```

On Bob:

```bash
mynet export --ip 10.42.0.2 --endpoint BOB_LAN_OR_WAN:51820 > /tmp/bob.toml
```

Copy the files (USB, scp, chat). Then:

```bash
# Alice
mynet peer import /tmp/bob.toml --name bob
mynet peer list

# Bob
mynet peer import /tmp/alice.toml --name alice
mynet peer list
```

**Pass:** Alice lists Bob at `10.42.0.2` with Bob's public key; Bob lists Alice at `10.42.0.1`.  
**Fail:** importing your own key (`refusing to add this node's own public key`).

Skip to Test 5 (`connect`) if you are not using the VPS. Tests 4+ assume the coordinator.

---

## 4. Join the coordinator

Do this **before** `connect`. Alice first, then Bob.

If the laptop has a stable public IP or a UDP 51820 port-forward, pass `--endpoint`. On a LAN, omit it.

**Alice**

```bash
mynet join \
  --coordinator "$VPS_IP:$COORD_PORT" \
  --token "$TOKEN" \
  --ip 10.42.0.1 \
  --endpoint "${ALICE_WAN:+$ALICE_WAN:51820}"
```

If `ALICE_WAN` is empty, drop `--endpoint` entirely:

```bash
mynet join \
  --coordinator "$VPS_IP:$COORD_PORT" \
  --token "$TOKEN" \
  --ip 10.42.0.1
```

**Bob** (explicit IP):

```bash
mynet join \
  --coordinator "$VPS_IP:$COORD_PORT" \
  --token "$TOKEN" \
  --ip 10.42.0.2
```

Or let the server pick the next free address (should be `10.42.0.2` after Alice took `.1`):

```bash
mynet join \
  --coordinator "$VPS_IP:$COORD_PORT" \
  --token "$TOKEN" \
  --allocate
```

Then on both:

```bash
mynet status
mynet peer list
mynet sync
```

**Pass:**

- `status` shows `Coordinator: $VPS_IP:$COORD_PORT` and `Join token: [set, not printed]`
- `status` never prints the token or a private key
- Alice's `peer list` contains Bob's public key and `10.42.0.2`
- Bob's `peer list` contains Alice's public key and `10.42.0.1`

**Fail:**

```bash
mynet join --coordinator "$VPS_IP:$COORD_PORT" --token 'wrong' --ip 10.42.0.9
# must error: invalid join token
```

On the VPS, `docker compose logs coordinator` should show `register` lines with public keys, **not** private keys.

---

## 5. Encrypted overlay ping (milestone)

This is the main test: Alice `10.42.0.1` ↔ Bob `10.42.0.2` over kernel WireGuard.

Laptop firewalls: allow UDP 51820 from the other machine if you can. Leave `connect` running in its own terminal.

**Alice**

```bash
sudo --preserve-env=MYNET_CONFIG_DIR mynet connect --ip 10.42.0.1
```

**Bob**

```bash
sudo --preserve-env=MYNET_CONFIG_DIR mynet connect --ip 10.42.0.2
```

`sudo` changes `HOME` to `/root`. After this repo's `SUDO_USER` lookup, `sudo mynet connect` uses the invoking user's `~/.config/mynet`. Until that binary is installed, pass the path explicitly:

```bash
sudo MYNET_CONFIG_DIR="$HOME/.config/mynet" mynet connect --ip 10.42.0.1
```

Do not run `mynet init` as root to "fix" a missing identity — that creates a second key under `/root`.

In a **second** terminal on each:

```bash
ip addr show mynet0
ip route show dev mynet0
sudo wg show mynet0
mynet status
```

**Pass (interface):**

- `mynet0` is UP with `10.42.0.1/24` (Alice) or `10.42.0.2/24` (Bob)
- route `10.42.0.0/24 dev mynet0`
- `wg show` lists the other peer's public key, `allowed ips: 10.42.0.2/32` (on Alice) / `.1/32` (on Bob)
- `latest handshake` becomes non-zero after traffic
- `mynet status` shows the other peer as `connecting` then `direct`

**Pass (data plane):**

```bash
# Alice
ping -c 5 10.42.0.2

# Bob
ping -c 5 10.42.0.1
```

Then something other than ping:

```bash
# Bob
python3 -m http.server 8080 --bind 10.42.0.2

# Alice
curl http://10.42.0.2:8080/
```

**Pass (not through the coordinator):** on the VPS, while ping is running:

```bash
sudo tcpdump -ni eth0 tcp port 9993
# or replace eth0 with the VPS WAN iface
```

You may see occasional TCP `join`/`sync` every ~30s. You must **not** see overlay ping volume on TCP 9993. Overlay is UDP 51820 **between the laptops** (or UDP `$RELAY_PORT` in Test 8).

```bash
# on Alice, physical iface (example wlan0)
sudo tcpdump -ni wlan0 udp port 51820
```

**Fail:** handshake stays `0`, ping 100% loss. Try Test 8 (relay). Do not mark Test 5 complete.

Leave `connect` running for Tests 6–7, or `Ctrl-C` / `sudo mynet disconnect` and reconnect.

---

## 6. Coordinator outage (session must survive)

With both `connect` processes still up and ping working:

**VPS**

```bash
docker compose stop coordinator
```

**Alice**

```bash
ping -c 5 10.42.0.2
```

**Pass:** ping still works. Overlay does not depend on the VPS.  
Logs on the laptops may warn `coordinator unreachable; WireGuard session unchanged`.

**VPS** — bring it back:

```bash
docker compose start coordinator
```

On a laptop:

```bash
mynet sync
```

**Pass:** sync succeeds again; ping never needed the VPS.

---

## 7. Status and handshake

While connected:

```bash
mynet status
sudo wg show mynet0
```

**Pass:** `status` lists the peer with state `direct` (or `connecting` / `relaying`). Token is redacted. After `disconnect`, `status` shows `disconnected` and `session.toml` is gone:

```bash
sudo --preserve-env=MYNET_CONFIG_DIR mynet disconnect
ls -l "$MYNET_CONFIG_DIR/session.toml"    # must not exist
mynet status
```

Reconnect before Test 8 if you disconnected.

---

## 8. Pair relay (only if Test 5 handshake fails)

Two NATs, no UDP 51820 port-forward: direct WG often never handshakes. This is the two-peer fallback.

**VPS**

```bash
docker compose up -d --build
docker compose ps
ss -lnu | grep 9994
```

**Pass:** `mynet-relay` is up, UDP `$RELAY_PORT` is open.

**Alice and Bob** (stop any previous `connect` first):

```bash
sudo --preserve-env=MYNET_CONFIG_DIR mynet disconnect

# Alice
sudo --preserve-env=MYNET_CONFIG_DIR mynet connect --ip 10.42.0.1 --relay "$VPS_IP:$RELAY_PORT"

# Bob
sudo --preserve-env=MYNET_CONFIG_DIR mynet connect --ip 10.42.0.2 --relay "$VPS_IP:$RELAY_PORT"
```

Wait ~15 seconds if a direct handshake is attempted first, then:

```bash
sudo wg show mynet0
# endpoint should become VPS_IP:RELAY_PORT after failover
ping -c 5 10.42.0.2    # from Alice
```

**Pass:** handshake non-zero, ping works, VPS `tcpdump -ni eth0 udp port 9994` sees traffic, TCP 9993 still does not carry ping.

**Fail / out of scope:** a third laptop. This relay only copies between two UDP sources.

Without Docker on the VPS:

```bash
export MYNET_LISTEN=0.0.0.0:9994
cargo run --release -p mynet-relay
```

---

## 9. Plaintext TUN+UDP (learning path, not the VPN)

Only if you want Phase 4. **Insecure.** Stop WireGuard `connect` first.

```bash
# Alice
sudo --preserve-env=MYNET_CONFIG_DIR mynet disconnect
sudo --preserve-env=MYNET_CONFIG_DIR mynet connect --plain --ip 10.42.0.1

# Bob
sudo --preserve-env=MYNET_CONFIG_DIR mynet connect --plain --ip 10.42.0.2
```

```bash
ping -c 3 10.42.0.2
```

**Pass:** ping may work on a LAN. This is **not** encrypted. Do not use on untrusted networks.  
**Label:** log line `WARNING: --plain`.

---

## 10. Hole-punch experiment (not the VPN)

Does not use WireGuard. Proves UDP mapped endpoints through a rendezvous.

**VPS** (needs Rust, or build `mynet-natpunch` elsewhere and copy the binary):

```bash
sudo ufw allow 3478/udp comment 'mynet hole-punch lab'
cargo run --release -p mynet-natpunch -- rendezvous --bind 0.0.0.0:3478
```

**Alice**

```bash
cargo run --release -p mynet-natpunch -- peer --rendezvous "$VPS_IP:3478" --id alice
```

**Bob** (start soon after Alice)

```bash
cargo run --release -p mynet-natpunch -- peer --rendezvous "$VPS_IP:3478" --id bob
```

**Pass:** both print `hole punch ok from …`  
**Expected fail:** two symmetric NATs. Record it; do not call that a product bug.

---

## 11. TUN smoke (single machine)

On Alice **or** Bob, with `connect` **down**:

```bash
sudo --preserve-env=MYNET_CONFIG_DIR mynet tun-test --ip 10.42.0.1 --duration 0
```

**Pass:** prints `TUN mynet0 10.42.0.1` and `ip addr` for the device, then exits (iface goes away when the process exits).  
**Fail without root:** message about `CAP_NET_ADMIN`.

---

## 12. Negative tests

| Action | Expected |
| --- | --- |
| `mynet join` with a wrong token | `invalid join token` |
| Alice `join --ip 10.42.0.1` then Bob `join --ip 10.42.0.1` | second register rejected (IP taken) |
| `mynet peer add --public-key "$OWN_KEY" --ip 10.42.0.9` | refusing own public key |
| `mynet peer add --ip 8.8.8.8` | overlay `10.42.0.0/24` required |
| `mynet identity` before `init` | identity not found |
| Second `mynet init` without `--force` | exit 1 |

---

## 13. Cleanup

**Alice / Bob**

```bash
sudo --preserve-env=MYNET_CONFIG_DIR mynet disconnect
sudo ip link del mynet0 2>/dev/null || true
```

**VPS**

```bash
docker compose down
# membership state is in the docker volume coordinator-state
# docker volume rm mynet_coordinator-state    # only if you want a blank coordinator
```

---

## Results log

Copy this table into notes when you actually run the lab. Do not mark a row pass unless you ran it.

| Test | Where | Result (pass / fail / skip) | Notes |
| --- | --- | --- | --- |
| 0 Coordinator listens | VPS | | |
| 1 `mynet version` / packages | Alice, Bob | | |
| 2 Identity, keys differ | Alice, Bob | | |
| 3 Manual export/import | Alice, Bob | | |
| 4 Join + peer list via VPS | Alice, Bob, VPS | | |
| 5 `ping 10.42.0.1` ↔ `.2` over WG | Alice, Bob | | handshake time? |
| 5 Overlay not on TCP 9993 | VPS tcpdump | | |
| 6 Coordinator stop, ping lives | Alice, VPS | | |
| 7 `status` / disconnect | Alice, Bob | | |
| 8 Relay ping | Alice, Bob, VPS | | |
| 9 `--plain` ping | Alice, Bob | | insecure |
| 10 Hole punch | Alice, Bob, VPS | | NAT type? |
| 11 `tun-test` | one laptop | | |
| 12 Negatives | Alice or Bob | | |

NAT type if known (home router): ________________

---

## Command cheat sheet

### VPS

```bash
cd mynet
cp .env.example .env          # edit token + ports
docker compose up -d --build
docker compose logs -f coordinator
docker compose up -d --build
docker compose ps
docker compose stop coordinator
docker compose start coordinator
docker compose down
ss -lnt | grep 9993
ss -lnu | grep 9994
```

### Alice (`10.42.0.1`)

```bash
export MYNET_CONFIG_DIR="$HOME/mynet-alice"
mynet init
mynet identity
mynet join --coordinator "$VPS_IP:$COORD_PORT" --token "$TOKEN" --ip 10.42.0.1
mynet status
mynet peer list
mynet sync
sudo --preserve-env=MYNET_CONFIG_DIR mynet connect --ip 10.42.0.1
sudo --preserve-env=MYNET_CONFIG_DIR mynet connect --ip 10.42.0.1 --relay "$VPS_IP:$RELAY_PORT"
ping -c 5 10.42.0.2
sudo wg show mynet0
sudo --preserve-env=MYNET_CONFIG_DIR mynet disconnect
```

### Bob (`10.42.0.2`)

```bash
export MYNET_CONFIG_DIR="$HOME/mynet-bob"
mynet init
mynet identity
mynet join --coordinator "$VPS_IP:$COORD_PORT" --token "$TOKEN" --ip 10.42.0.2
mynet status
mynet peer list
sudo --preserve-env=MYNET_CONFIG_DIR mynet connect --ip 10.42.0.2
ping -c 5 10.42.0.1
sudo --preserve-env=MYNET_CONFIG_DIR mynet disconnect
```
