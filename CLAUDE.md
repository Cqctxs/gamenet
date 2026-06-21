# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build everything
cargo build

# Build release binaries
cargo build --release

# Run the relay server (binds to 0.0.0.0:5000)
cargo run -p gamenet-server

# Run the CLI agent (connects to a relay server)
cargo run -p gamenet-cli -- host minecraft
cargo run -p gamenet-cli -- host --port 7777 --server 1.2.3.4

# Run all tests
cargo test

# Run a single test
cargo test -p gamenet-core test_name

# Run integration tests
cargo test --test integration_test

# Check with linting
cargo clippy --all-targets

# Format code
cargo fmt
```

## Architecture

Three-crate Cargo workspace. The transport layer between server and agent is **always QUIC** (via `quinn`). The server binds one UDP port (5000) for all incoming agent connections; everything else—control signals, TCP streams, UDP datagrams—is multiplexed over this single QUIC connection.

### Crates

- **`gamenet-core`** — shared types used by both binaries:
  - `protocol.rs` — `ControlMessage` enum and `Protocol` enum (serialized with `bincode`, framed with a 4-byte length prefix)
  - `message.rs` — `send_msg` / `recv_msg` helpers for framed bincode over QUIC streams
  - `crypto.rs` — TLS certificate generation (`server_config()`) and `insecure_client_config()` (skips cert verification; dev-only)
  - `presets.rs` — `PRESETS` table mapping game names to ports and protocols

- **`gamenet-server`** — the cloud relay:
  - `relay.rs` — `RelayServer`: accepts QUIC connections from agents (0.5-RTT / 0-RTT)
  - `tunnel.rs` — `Tunnel`: handles the per-agent QUIC connection; opens a TCP listener on a dynamically assigned public port (starting at 10000) and creates a new QUIC bi-stream per player
  - `bridge.rs` — `bridge_tcp_to_quic`: pumps bytes between a player's TCP socket and a QUIC bi-stream
  - `state.rs` — `ServerState`: shared `Arc<Mutex<ServerState>>` that maps public ports to active tunnels

- **`gamenet-cli`** — the agent that runs on the game host:
  - `tunnel.rs` — `AgentTunnel`: connects to the relay via QUIC, sends `Register`, waits for `TunnelReady`, then loops accepting new QUIC bi-streams (one per player)
  - `bridge.rs` — `bridge_to_local`: connects back to `localhost:<local_port>` via TCP and pumps bytes to/from the QUIC stream

### Data flow (TCP game)

```
Player TCP → server TCP listener (public port)
  → server opens QUIC bi-stream → agent
  → agent connects TCP to localhost:<local_port>
  → bidirectional byte pump
```

The server notifies the agent of each new player via a `NewConnection { stream_id }` control message, then immediately opens the QUIC bi-stream for data. The agent's `run()` loop accepts those bi-streams and handles them concurrently via `tokio::spawn`.

### Key design decisions

- **0-RTT / 0.5-RTT**: Server uses `into_0rtt()` on incoming connections; client attempts `into_0rtt()` on reconnections for fast handshakes. First connections fall back to 1-RTT.
- **Self-signed TLS (dev)**: `crypto::server_config()` generates a fresh self-signed cert on each server start. The client uses `insecure_client_config()` which skips all cert verification. Production use would require proper cert pinning.
- **Port allocation**: `ServerState` assigns sequential public ports starting at 10000, incrementing per tunnel. Ports are reclaimed when the agent disconnects.
- **Control stream**: Stream 0 (first bi-stream) is the control channel. All subsequent bi-streams carry player data.
