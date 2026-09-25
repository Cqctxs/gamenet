# GameNet: Architecture & Implementation Guide

**Project Goal:** A high-performance gaming tunnel written in Rust.  
**Core differentiator:** TCP game traffic is carried over QUIC rather than another TCP tunnel. UDP game forwarding remains a planned feature.

**Current implementation:** TCP game tunnels only. The relay-to-agent link uses QUIC with TLS 1.3 and requires the `X25519MLKEM768` hybrid key-exchange group on both sides. Certificate authentication is still conventional, and the player-to-relay TCP hop is not encrypted by GameNet. The relay binds an available TCP port in `10000..=10999`, holds it for five minutes after disconnect, and the CLI retries lost connections. UDP forwarding and QUIC 0-RTT are future work. Sections below describing UDP are design goals, not shipped features.

The relay permits two active or reconnect-window host leases and four pending registrations per IPv4 address or IPv6 `/64` network. Pending registrations also have a global cap of 128 and a ten-second deadline. A live host can wait indefinitely for players; these quotas are address-based admission controls, not an identity or account system.

The host keeps its ordinary 32-byte identity token and a separate 32-byte recovery key in private files on Unix and Windows. Registration enrolls only a hash of the recovery key; reconnecting with the ordinary token cannot change an enrolled recovery key. A recovery request proves knowledge of the key over verified QUIC, durably transfers the live claim to a new ordinary token, and closes any displaced QUIC connection. Routine rotation transfers a disconnected claim without the recovery key and is limited to once per lease. The persisted lease records retired token fingerprints and the recovery fingerprint; these disappear when the five-minute claim expires. Recovery protects a claim from theft of the ordinary identity alone, but the public anonymous relay cannot ban a person from opening a new unrelated tunnel.

---

## 1. System Overview
The system consists of three crates in a Cargo Workspace:

| Crate            | Role                                     | Runs On      |
| ---------------- | ---------------------------------------- | ------------ |
| `gamenet-server` | Public relay that accepts player traffic | Cloud server |
| `gamenet-cli`    | Agent that forwards to localhost         | Your machine |
| `gamenet-core`   | Shared protocol definitions              | Both         |

**The Golden Rule:** The connection between Agent and Server is **always QUIC** via the `quinn` crate. It currently carries control signals and TCP streams.

---

## 2. Why QUIC?

### The Problem: TCP Meltdown

When you tunnel TCP (Minecraft) over TCP (the internet), packet loss causes **compounding lag**:

```
Normal TCP:     [packet lost] → retransmit → 100ms delay
TCP over TCP:   [packet lost] → outer retransmit → inner retransmit → 500ms+ delay
```

### The Solution: QUIC

QUIC runs over UDP and provides:

- **Streams:** Independent reliable channels (no head-of-line blocking)
- **Datagrams:** Unreliable fire-and-forget packets (perfect for UDP games)
- **Built-in TLS:** Encryption is mandatory
- **Reconnects:** The CLI starts a new authenticated handshake after a lost connection; registration is never sent as replayable 0-RTT data.

---

## 3. Feature Breakdown

### Feature A: Hybrid Transport Engine (QUIC)

**Goal:** One encrypted relay-to-agent connection carrying TCP streams today, with UDP datagrams planned.

**Implementation:**

- **Library:** `quinn` (Rust's QUIC implementation)
- **Architecture:**
  - Server binds one UDP port (e.g., `5000`) for all agents
  - TLS via `rustls` (QUIC requires encryption)
  - Control messages sent via dedicated QUIC stream
  - Serialization via `bincode` (faster/smaller than JSON)

---

### Feature B: TCP Game Tunneling (Minecraft Java, Terraria)

**Flow:**

```
1. Player connects to relay.example.com:25565 (TCP)
2. Server accepts TCP socket
3. Server opens new QUIC Stream to Agent
4. Server bridges: TCP ↔ QUIC Stream
5. Agent accepts QUIC Stream
6. Agent connects to localhost:25565 (TCP)
7. Agent bridges: QUIC Stream ↔ TCP
```

**Key code pattern:**

```rust
// QUIC has separate send and receive halves. Each direction drains to EOF.
gamenet_core::bridge::copy_halves(tcp_read, tcp_write, quic_recv, quic_send).await?;
```

---

### Feature C: UDP Game Tunneling (planned; not implemented)

**Flow:**

```
1. Player sends UDP packet to relay.example.com:2456
2. Server wraps packet + sender metadata
3. Server sends via QUIC Datagram (unreliable, fast)
4. Agent receives Datagram
5. Agent forwards to localhost:2456 (UDP)
6. localhost replies → Agent sends Datagram back → Server → Player
```

**Why unreliable?** Games already handle packet loss. Re-adding reliability would just add latency. If a packet drops, we let it drop.

---

### Feature D: Game Presets

**Goal:** Users type `gamenet host minecraft` instead of remembering ports.

**Implementation:**

```rust
pub struct GamePreset {
    pub name: &'static str,
    pub protocol: Protocol,
    pub default_port: u16,
}

// Embedded in binary
pub const PRESETS: &[GamePreset] = &[
    GamePreset { name: "minecraft",  protocol: Protocol::Tcp,  default_port: 25565 },
    GamePreset { name: "bedrock",    protocol: Protocol::Udp,  default_port: 19132 },
    GamePreset { name: "valheim",    protocol: Protocol::Udp,  default_port: 2456  },
    GamePreset { name: "terraria",   protocol: Protocol::Tcp,  default_port: 7777  },
    GamePreset { name: "factorio",   protocol: Protocol::Udp,  default_port: 34197 },
];
```

---

### Feature E: Connection Resumption (planned)

**Goal:** Survive brief network interruptions without dropping players.

**Implementation:**

- The current CLI retries with a full authenticated handshake and reclaims its port within five minutes. Existing player streams do not survive a disconnect.

---

### Feature F: Rate Limiting

**Goal:** Prevent abuse of the relay server.

**Implementation:**

- Per-tunnel bandwidth limits
- Maximum connections per tunnel
- Token-bucket rate limiting

---

## 4. Data Structures

Place these in `crates/core/src/protocol.rs`:

```rust
use serde::{Deserialize, Serialize};

/// Control messages sent over Stream 0 (the control stream)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ControlMessage {
    // ─── Client → Server ───────────────────────────────────────

    /// Register a new tunnel
    Register {
        protocol: Protocol,
        local_port: u16,
        game_preset: Option<String>,
    },

    /// Keep-alive ping
    Ping,

    // ─── Server → Client ───────────────────────────────────────

    /// Tunnel is ready, here's the public address
    TunnelReady {
        public_host: String,
        public_port: u16,
    },

    /// Keep-alive response
    Pong,

    /// Something went wrong
    Error { message: String },

    /// A new player connection is incoming (for TCP tunnels)
    NewConnection { stream_id: u64 },
}

/// Supported protocols
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,   // Minecraft Java, Terraria
    Udp,   // Valheim, Bedrock, FPS games
    Both,  // Some games use both
}

/// Header prepended to UDP datagrams
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DatagramHeader {
    /// Original sender's address (e.g., "1.2.3.4:12345")
    pub source_addr: String,
    /// Which local port this belongs to
    pub local_port: u16,
}
```

---

## 5. Dependencies

Add to workspace `Cargo.toml`:

```toml
[workspace.dependencies]
# Async runtime
tokio = { version = "1", features = ["full"] }

# QUIC implementation
quinn = "0.11"
rustls = { version = "0.23", default-features = false, features = ["ring", "std"] }
rcgen = "0.13"  # Certificate generation

# Serialization
serde = { version = "1", features = ["derive"] }
bincode = "1"

# Error handling
anyhow = "1"
thiserror = "2"

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# CLI
clap = { version = "4", features = ["derive"] }

# Utilities
bytes = "1"
```

---

## 6. Implementation Roadmap

### Phase 1: The Foundation (Week 1-2)

- [ ] Set up workspace with dependencies
- [ ] Generate self-signed TLS certificates (dev mode)
- [ ] Establish QUIC connection (client ↔ server)
- [ ] Implement control protocol (Register, TunnelReady, Ping/Pong)
- [ ] Test: Client connects, stays alive, reconnects on drop

### Phase 2: TCP Tunneling (Week 2-3)

- [ ] Server: Accept TCP connections on public port
- [ ] Server: Create QUIC stream per TCP connection
- [ ] Client: Accept QUIC stream, connect to localhost
- [ ] Implement bidirectional byte pumping
- [ ] Handle connection cleanup
- [ ] Test: netcat through tunnel, then Minecraft

### Phase 3: UDP Tunneling (Week 3-4)

- [ ] Server: Bind UDP socket, receive datagrams
- [ ] Server: Forward via QUIC datagrams
- [ ] Client: Receive datagrams, forward to localhost
- [ ] Handle return path
- [ ] Test: Valheim or Minecraft Bedrock

### Phase 4: Polish & Safety (Week 4-5)

- [ ] Add game presets
- [ ] Evaluate replay-safe connection resumption
- [ ] Add basic rate limiting
- [ ] Add proper error handling and logging
- [ ] Add graceful shutdown

### Future Phases (v2)

- [ ] TUI dashboard (`ratatui`)
- [ ] Peer-to-peer mode (use relay as STUN/TURN)
- [ ] Authentication system
- [ ] Web dashboard

---

## 7. Project Structure

```
gamenet/
├── Cargo.toml              # Workspace definition
├── ARCHITECTURE.md         # This file
├── crates/
│   ├── core/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── protocol.rs # ControlMessage, Protocol, etc.
│   │       └── presets.rs  # Game presets
│   ├── server/
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── relay.rs    # QUIC server logic
│   │       ├── tcp.rs      # TCP listener + bridging
│   │       └── udp.rs      # UDP socket + bridging
│   └── cli/
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs
│           ├── tunnel.rs   # QUIC client logic
│           └── bridge.rs   # Local connection bridging
└── tests/
    └── integration_test.rs
```
