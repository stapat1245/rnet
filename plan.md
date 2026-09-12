# Project Plan

## Project Goal

Build a small, understandable Linux P2P VPN in Rust.

Each node has a cryptographic identity, a virtual IPv4 address, and an encrypted UDP path to trusted peers. Direct P2P is the default data path. A coordination server may exist later for discovery only. A relay may exist later as a fallback. The coordination server must never carry VPN payload.

This is not a Tailscale clone. Cryptography is not invented here. Encryption is WireGuard.

## Current Status

**Phase 0 COMPLETE. Phase 1 COMPLETE.** Next: Phase 2 (local trusted-peer model).

Verified 2026-09-13 on this machine:

* `cargo test --workspace` — 24 tests passed (cli 2 unit + 8 integration, core 2, identity 12)
* `mynet --help`, `mynet version`, `mynet --version` exit 0
* `mynet init` then `mynet identity` round-trip; second `init` without `--force` fails
* Two config directories produce different public keys
* Identity file mode is `0600`; private key is not printed

Platform: Ubuntu 24.04.4 LTS, kernel 7.0.0-31-generic, `rustc 1.75.0` from the distro (no rustup). `wireguard-tools` 1.0.20210914 and in-tree `wireguard.ko` 1.0.0 are present. `CONFIG_TUN=y`. In the development sandbox `/dev/net/tun` was not visible; TUN/WireGuard interface creation was **not** executed. Phase 3 remains blocked on a usable TUN node plus `CAP_NET_ADMIN`.

## Architecture

Layers stay separate in code and documentation:

| Layer | Question it answers | Initial mechanism |
| --- | --- | --- |
| Identity | Who is this peer? | X25519 keypair; peer ID derived from public key |
| Discovery | Where is the peer reachable? | Manual endpoints first; coordinator later |
| NAT traversal | Can we get a direct UDP path? | Deferred (Phase 10) |
| Transport | How do packets move on the wire? | UDP |
| Virtual networking | How does Linux inject/receive overlay packets? | Linux TUN, IPv4 |
| Encryption | How is payload protected? | Kernel WireGuard |

Control plane: identity, peer list, endpoints, coordination, NAT negotiation.

Data plane: encrypted VPN packets between peers. Never through the coordinator.

Workspace (kept small while the project is young):

```text
mynet/
├── Cargo.toml              workspace
├── plan.md
├── notes.md
├── README.md
└── crates/
    ├── mynet-cli/          clap binary (`mynet`)
    ├── mynet-core/         shared constants and paths
    └── mynet-identity/     X25519 identity (Phase 1)
```

Further crates (`mynet-vpn`, `mynet-transport`, `mynet-protocol`, `mynet-coordinator`) are added when a phase actually needs them. Empty crates are not created for decoration.

Default overlay: `10.42.0.0/24`. Default interface name: `mynet0`. Default WireGuard/UDP port: `51820`.

## Phase 0

**Status:** COMPLETE

### Objective

Prepare the repository without implementing the VPN. Produce a compiling CLI, documentation, and recorded environment facts.

### Prerequisites

Linux host with Rust. No VPN functionality required.

### Implementation tasks

- [x] Inspect repository (it was empty)
- [x] Inspect OS, rustc, TUN, WireGuard, networking tools
- [x] Choose workspace layout and dependencies
- [x] Create `plan.md`, `notes.md`, `README.md`
- [x] Implement `mynet --help` and `mynet version`
- [x] Compile
- [x] Run tests
- [x] Record actual results

### Tests

* Unit: help text mentions `version`; version string includes `mynet` and `0.1.0`
* Integration: `mynet --help`, `mynet version`, and `mynet --version` exit 0
* Core: `MYNET_CONFIG_DIR` override; identity path lives under config dir

Ran: `cargo test --workspace` (2026-09-13). All tests passed.

### Manual verification

```bash
cargo run -p mynet-cli -- --help
cargo run -p mynet-cli -- version
cargo run -p mynet-cli -- --version
```

All three succeeded. `wg --version` reports `wireguard-tools v1.0.20210914`. TUN interface creation was **not** run (sandbox/host-mutation restriction; `/dev/net/tun` not visible in the sandbox).

### Exit criteria

* Project compiles — yes
* CLI runs — yes
* Documentation exists — yes
* Architecture decisions recorded — yes
* Environment limitations recorded honestly — yes

### Known limitations

* No VPN data plane yet
* rustc 1.75 forces exact crate pins (see `notes.md`)
* TUN/WireGuard device creation not verified in this environment
* Single machine; two-host tests cannot run yet

## Phase 1

**Status:** COMPLETE

### Objective

Give every installation a persistent cryptographic identity: private key, public key, peer ID. Never print or transmit the private key by default.

### Prerequisites

Phase 0 complete.

### Implementation tasks

- [x] Generate X25519 identity (`x25519-dalek`)
- [x] Persist to `identity.toml` with mode `0600`
- [x] Load and re-derive public key / peer ID
- [x] Validate permissions (reject group/other bits)
- [x] `mynet init` and `mynet identity`
- [x] Clean errors for missing/corrupt files

### Tests

* New identity generation
* Reload
* Deterministic public key from the same private key
* Malformed key handling
* Missing file handling
* Insecure permissions rejected (Unix)
* CLI round-trip, `--force`, two isolated config dirs

`mynet-identity` 12 unit tests + CLI integration tests listed above: all passed.

### Manual verification

```bash
cargo run -p mynet-cli -- --config-dir /tmp/mynet-a init
cargo run -p mynet-cli -- --config-dir /tmp/mynet-a identity
```

Observed: `Peer ID` and `Public Key` printed; no `Private Key` line; file mode `600`; second `init` without `--force` exits 1 with a `--force` hint. Two config dirs produced different public keys (CLI integration test `two_config_dirs_get_independent_identities`).

### Exit criteria

Two machines (or two config dirs) can independently generate identities and display public keys. **Met** via two config directories.

### Known limitations

Identity is local only. No network, no peer trust yet. Peer ID is a SHA-256 fingerprint of the public key (16 bytes, hex), not the WireGuard public key string itself. The public key remains the cryptographic identity.

## Phase 2

**Status:** NOT STARTED

### Objective

Local model of a trusted peer, plus `mynet peer add|list|remove`.

A peer is trusted only by its public key. An endpoint, hostname, or claimed name is not identity. Cryptographic proof of the corresponding private key is required before traffic is trusted (enforced in Phase 5/7 via WireGuard).

### Prerequisites

Phase 1 complete.

### Implementation tasks

- [ ] `Peer`, `PeerId`, `PeerState` types
- [ ] Persist trusted peers in `peers.toml`
- [ ] CLI add/list/remove
- [ ] Document what “trusted” means

### Tests

* Add/list/remove round trip
* Reject duplicate peer IDs / public keys
* Reject invalid public keys and IPv4 addresses
* Endpoint parse errors

### Manual verification

Add a fake peer by public key and virtual IP; list it; remove it.

### Exit criteria

A node can store and display a trusted peer without talking to the network.

### Known limitations

No handshake. Storing a public key is a trust decision, not authentication of live traffic.

## Phase 3

**Status:** NOT STARTED

### Objective

Create a Linux TUN (`mynet0`), assign IPv4, bring it up, read/write packets, clean up. No encryption.

### Prerequisites

Phase 2. `CAP_NET_ADMIN` or root.

### Implementation tasks

- [ ] Open `/dev/net/tun`, `TUNSETIFF`
- [ ] Configure address `10.42.0.1/24` (or configured)
- [ ] Bring link up
- [ ] Read/write packet loop
- [ ] `sudo mynet tun-test`
- [ ] Cleanup on exit

### Tests

* Packet buffer framing (unit)
* Privileged integration if the environment allows

### Manual verification

```bash
sudo mynet tun-test
ip addr show mynet0
ip link show mynet0
ip route
```

Record output in `notes.md`.

### Exit criteria

Linux treats `mynet0` as a real interface; the process can observe packets destined to it.

### Known limitations

Unencrypted. No second host. Requires root.

## Phase 4

**Status:** NOT STARTED

### Objective

Two hosts exchange packets over TUN + UDP. Experimental forwarding may be plaintext, clearly labeled as not the final protocol.

### Prerequisites

Phase 3 on two Linux machines, or two network namespaces, with direct UDP connectivity.

### Implementation tasks

- [ ] UDP bind/send/recv
- [ ] Map virtual IP to endpoint
- [ ] TUN → UDP → TUN forwarding
- [ ] Document that this is insecure

### Tests

* UDP framing
* Namespace-based integration if possible

### Manual verification

`ping 10.42.0.2` from Alice. TCP if practical.

### Exit criteria

Application packet from Alice reaches Bob's virtual interface; return traffic works.

### Known limitations

Not encrypted. Manual endpoints. No NAT.

## Phase 5

**Status:** NOT STARTED

### Objective

Replace experimental forwarding with kernel WireGuard. No plaintext VPN payload on the physical network.

### Prerequisites

Phase 4 path understood. Kernel WireGuard available.

### Implementation tasks

- [ ] Create `wireguard` interface (or convert `mynet0`)
- [ ] Load local private key
- [ ] Configure peer public key, endpoint, allowed IPs
- [ ] Verify with `tcpdump` that payload is not plaintext

### Tests

* Config rendering / allowed-IP mapping
* Privileged two-namespace test if possible

### Manual verification

Ping plus `tcpdump` on the physical interface.

### Exit criteria

Ping works; capture shows WireGuard, not ICMP plaintext, on the physical NIC.

### Known limitations

Still manual endpoints. Linux only.

## Phase 6

**Status:** NOT STARTED

### Objective

Fully decentralized first version: Alice and Bob manually exchange public keys, virtual IPs, and endpoints. Prove that a coordinator is not required for authentication.

### Prerequisites

Phase 5.

### Implementation tasks

- [ ] Document exchange procedure
- [ ] CLI helpers to print/import peer records
- [ ] Connect with only local config

### Tests

Import/export of a peer record.

### Manual verification

Two hosts, no coordinator, encrypted ping.

### Exit criteria

Direct encrypted P2P from files exchanged out of band.

### Known limitations

Endpoint changes require manual updates.

## Phase 7

**Status:** NOT STARTED

### Objective

Reject peers that do not match the expected identity. Rely on WireGuard's handshake, not a custom crypto protocol.

### Prerequisites

Phase 6.

### Implementation tasks

- [ ] Associate public key, peer ID, virtual IP, endpoint
- [ ] Reject mismatched allowed IPs / unknown keys
- [ ] Document threat model

### Tests

Unknown peer, wrong public key, stale endpoint handling (as applicable).

### Manual verification

Traffic from an untrusted key does not decrypt into the overlay.

### Exit criteria

Only configured public keys can send overlay traffic.

### Known limitations

Does not solve stolen private keys. Coordinator compromise is N/A until Phase 8.

## Phase 8

**Status:** NOT STARTED

### Objective

Optional coordination service for registration, presence, public-key lookup, and candidate endpoints. Must not proxy VPN packets.

### Prerequisites

Phase 7.

### Implementation tasks

- [ ] Minimal coordinator protocol
- [ ] Store as little as practical
- [ ] Node works for already-established direct sessions if coordinator dies

### Tests

Register/discover; coordinator outage does not tear down documented data-plane behavior.

### Manual verification

Alice and Bob find each other through coordinator; ping still does not traverse the coordinator.

### Exit criteria

Coordinator is control-plane only.

### Known limitations

No NAT traversal yet.

## Phase 9

**Status:** NOT STARTED

### Objective

Publish and learn current UDP endpoints. Treat endpoints as dynamic. Public key remains identity.

### Prerequisites

Phase 8.

### Implementation tasks

- [ ] Periodic endpoint publish
- [ ] Apply updated endpoints to WireGuard peer config

### Tests

Endpoint update without identity change.

### Manual verification

Change UDP port; peer reconnects.

### Exit criteria

A peer can move without minting a new key.

### Known limitations

Symmetric NAT still fails.

## Phase 10

**Status:** NOT STARTED

### Objective

Document NAT, then a standalone hole-punching experiment, then optional integration. Do not assume success for every NAT type.

### Prerequisites

Phase 9. Written NAT notes before code.

### Implementation tasks

- [ ] Write NAT section in `notes.md` before implementation
- [ ] Standalone UDP hole-punch experiment
- [ ] Record failures explicitly

### Tests

Same-LAN vs distinct-NAT scenarios that this lab can actually create.

### Manual verification

Two NATed peers, if available.

### Exit criteria

Documented behavior for the NAT types actually tested. Failures recorded.

### Known limitations

Symmetric NAT often cannot hole-punch.

## Phase 11

**Status:** NOT STARTED

### Objective

Explicit per-peer connection state machine with traced transitions.

### Prerequisites

Phases 5–9 (relay state lands in Phase 13).

### Implementation tasks

- [ ] `Disconnected → Discovering → Connecting → Direct | Relaying | Failed`
- [ ] `tracing` on every transition

### Tests

State transition table.

### Manual verification

`mynet status` reflects states (when CLI exists).

### Exit criteria

Connection logic is not scattered.

### Known limitations

Relay branch unused until Phase 13.

## Phase 12

**Status:** NOT STARTED

### Objective

Keepalives, NAT binding refresh, endpoint changes, sleep/wake.

### Prerequisites

Phase 11.

### Implementation tasks

- [ ] UDP keepalives
- [ ] Re-resolve/re-publish after network change

### Tests

Keepalive interval; stale endpoint replacement.

### Manual verification

Idle connection survives typical NAT timeout if testable.

### Exit criteria

Long-lived direct sessions do not silently die without logs.

### Known limitations

Cannot fully test laptop sleep here.

## Phase 13

**Status:** NOT STARTED

### Objective

Relay fallback. Relay forwards opaque encrypted packets only. No private keys, no plaintext.

### Prerequisites

Direct P2P works (Phase 5+). Distinct from coordinator.

### Implementation tasks

- [ ] Relay protocol
- [ ] Fail over when direct connect fails

### Tests

Relay does not need keys to forward; payload remains opaque.

### Manual verification

Force direct failure; ping still works via relay.

### Exit criteria

Relay is optional and ciphertext-only.

### Known limitations

Relay sees endpoints and timing. Not a privacy network.

## Phase 14

**Status:** NOT STARTED

### Objective

Address assignment. Start with explicit config (`Alice=10.42.0.1`, `Bob=10.42.0.2`). Coordinator-assisted allocation later. No consensus.

### Prerequisites

Working overlay.

### Implementation tasks

- [ ] Explicit allocation first
- [ ] Optional coordinator allocator later

### Tests

Conflict detection for duplicate virtual IPs.

### Manual verification

Two peers get distinct addresses.

### Exit criteria

No silent IP collision in the explicit-config design.

### Known limitations

Not decentralized allocation.

## Phase 15

**Status:** NOT STARTED

### Objective

Host routes overlay traffic through the VPN interface. Cleanup after crashes.

### Prerequisites

Working interface.

### Implementation tasks

- [ ] Install `10.42.0.0/24 dev mynet0`
- [ ] Remove on disconnect
- [ ] Document conflicts

### Tests

Route install/remove helpers.

### Manual verification

`ping`, `ssh`, `curl` to overlay IPs behave naturally.

### Exit criteria

Applications need no special sockets.

### Known limitations

No IPv6. No mesh to foreign subnets.

## Phase 16

**Status:** NOT STARTED

### Objective

Clean CLI: `init`, `identity`, `peer`, `connect`, `status`, `disconnect`. `status` must be useful. `doctor` later.

### Prerequisites

Earlier commands exist incrementally.

### Implementation tasks

- [ ] Prioritize init/identity/peer/connect/status/disconnect
- [ ] Human-readable status

### Tests

CLI parsing and status formatting.

### Manual verification

Operator can understand a session from `status` alone.

### Exit criteria

Core operator loop works without reading source.

### Known limitations

No web UI. No MagicDNS.

## Testing Strategy

* Unit tests for identity, config, serialization, state machine, parsing
* Integration tests for CLI and, where privileges allow, TUN/UDP
* End-to-end: ping, TCP, SSH, restart, endpoint change — only when two hosts or netns exist
* NAT combinations documented as actually tested, never invented

This environment today: rustc 1.75, one machine, TUN/WireGuard interface creation not verified from the sandbox. Privileged and two-host tests are recorded as untested until they run.

## Milestones

1. **Encrypted LAN/direct P2P ping** between two Linux hosts (`10.42.0.1` ↔ `10.42.0.2`) via TUN → WireGuard → UDP. Not NAT traversal.
2. **Coordinator-assisted discovery** with VPN traffic still Alice ══ Bob, never Alice → coordinator → Bob.
3. **UDP hole punching** across common NATs, with failures recorded.

## Known Risks

* rustc 1.75 vs modern crates (edition 2024). Mitigated by exact pins and committed `Cargo.lock`.
* TUN/WireGuard need `CAP_NET_ADMIN`. Cannot fully verify Phases 3+ without root.
* Single host: two-machine milestone cannot be claimed here.
* Kernel WireGuard netlink crates may not compile on 1.75; Phase 5 may use `ip`/`wg` CLI first.
* NAT hole punching is unreliable on symmetric NAT.
* `/dev/net/tun` is world-writable on this host (`crw-rw-rw-`). Opening the device succeeded unprivileged; `TUNSETIFF` still failed. Treat this as a local hardening issue, not as unprivileged interface creation.

## Deferred Work

IPv6, Windows/macOS/Android/iOS, MagicDNS, ACLs, SSO, web dashboard, DERP-compatible protocol, mesh routing to foreign subnets, Kubernetes, multi-region coordinators, decentralized IP consensus.

## Future Extensions

Userspace WireGuard (boringtun) if kernel WireGuard is missing. Netlink-native configuration once the toolchain is newer. Optional relay. Coordinator-assisted allocation. `mynet doctor`.
