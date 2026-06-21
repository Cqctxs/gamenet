# Tunnel Identity, Stable URLs & Security Hardening — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give each CLI agent a stable 32-byte identity token so it always gets the same public port across reconnections and server restarts, replace the unbounded sequential port allocator with a capped token-keyed pool, and close several OOM, resource-exhaustion, and rate-limit vulnerabilities.

**Architecture:** On first run the CLI generates a random 32-byte token and saves it to `~/.config/gamenet/identity.bin`; every subsequent run loads that same token. The token travels in the `Register` control message. The server maintains a permanent `token → port` mapping in an in-memory HashMap that is serialised to `./gamenet-state.json` on every change, so the same agent always gets the same public port even after a server restart. Port numbers are drawn from a fixed pool (10000–10999), capping total tunnels at 1 000. Security hardening adds a 64 KB control-message cap (OOM fix), a per-IP tunnel limit of 5, and a per-tunnel concurrent-player cap of 50.

**Tech Stack:** Rust workspace (`gamenet-core`, `gamenet-server`, `gamenet-cli`), `quinn` 0.11, `bincode` (wire), `serde_json` (state persistence), `getrandom` 0.2 (token generation)

---

## Security issues in the current system

| # | Vulnerability | Exploitability | Fixed in |
|---|---------------|----------------|----------|
| 1 | `recv_msg` allocates `vec![0u8; len]` with no cap on the u32 length — send `0xFFFFFFFF`, OOM crash | Trivial, one packet | Task 1 |
| 2 | Port allocator never stops — attacker opens 55 535 connections to exhaust every TCP port | Low effort | Task 5 |
| 3 | Each TCP player connection spawns an unbounded tokio task — flood the public port, exhaust memory | Trivial with netcat loop | Task 6 |
| 4 | No per-IP connection limit — one host can open hundreds of QUIC connections | Trivial | Task 5 |
| 5 | No auth — any host on the internet can use your relay as a free proxy | Trivial | Tasks 3–5 (token is soft barrier; no allowlist yet) |
| 6 | `insecure_client_config` skips TLS cert verification — MITM trivial on hostile networks | Requires positioning | **Out of scope** (needs cert pinning or CA) |
| 7 | No QUIC-level address validation / rate limiting | Requires spoofed UDP | **Out of scope** (quinn Retry partially mitigates) |

---

## File map

| Action | Path | Responsibility |
|--------|------|----------------|
| Modify | `crates/core/src/message.rs` | 64 KB message size cap |
| Modify | `crates/core/Cargo.toml` | Add `getrandom = "0.2"` |
| Create | `crates/core/src/identity.rs` | Generate/persist 32-byte token |
| Modify | `crates/core/src/lib.rs` | Export `identity` module |
| Modify | `crates/core/src/protocol.rs` | Add `token: [u8; 32]` to `Register` |
| Modify | `crates/server/Cargo.toml` | Add `serde_json = "1"` |
| Modify | `crates/server/src/state.rs` | Token registry, port pool, IP limits, JSON persistence |
| Modify | `crates/server/src/tunnel.rs` | Accept `peer_ip`, player cap, updated cleanup |
| Modify | `crates/server/src/relay.rs` | Pass `peer_ip` into `Tunnel::from_quic` |
| Modify | `crates/cli/src/tunnel.rs` | Load identity token, send in Register, fix default server |

---

### Task 1: Cap control message sizes in `recv_msg`

**Files:**
- Modify: `crates/core/src/message.rs`

- [ ] **Step 1: Write the failing test**

Append to `crates/core/src/message.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn recv_msg_rejects_oversized_length() {
        let (mut writer, mut reader) = duplex(1024);
        // Claim a 200 KB message — above the 64 KB cap
        writer.write_all(&200_000_u32.to_be_bytes()).await.unwrap();
        drop(writer);

        let err = recv_msg(&mut reader).await.unwrap_err();
        assert!(err.to_string().contains("too large"), "got: {}", err);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test -p gamenet-core recv_msg_rejects_oversized_length
```

Expected: FAIL — current code reads 200 000 bytes, gets EOF, returns `Ok(None)` instead of an error.

- [ ] **Step 3: Add the size cap**

Replace the full contents of `crates/core/src/message.rs`:

```rust
use crate::protocol::ControlMessage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_CONTROL_MSG_BYTES: usize = 64 * 1024;

pub async fn send_msg<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &ControlMessage,
) -> anyhow::Result<()> {
    let payload = bincode::serialize(msg)?;
    let len = (payload.len() as u32).to_be_bytes();
    writer.write_all(&len).await?;
    writer.write_all(&payload).await?;
    Ok(())
}

pub async fn recv_msg<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> anyhow::Result<Option<ControlMessage>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_CONTROL_MSG_BYTES {
        return Err(anyhow::anyhow!(
            "Control message too large: {} bytes (max {})",
            len,
            MAX_CONTROL_MSG_BYTES
        ));
    }
    let mut data = vec![0u8; len];
    reader.read_exact(&mut data).await?;
    Ok(Some(bincode::deserialize(&data)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn recv_msg_rejects_oversized_length() {
        let (mut writer, mut reader) = duplex(1024);
        writer.write_all(&200_000_u32.to_be_bytes()).await.unwrap();
        drop(writer);

        let err = recv_msg(&mut reader).await.unwrap_err();
        assert!(err.to_string().contains("too large"), "got: {}", err);
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cargo test -p gamenet-core recv_msg_rejects_oversized_length
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/message.rs
git commit -m "fix: cap control messages at 64 KB to prevent OOM"
```

---

### Task 2: Add `getrandom` and `serde_json` dependencies

**Files:**
- Modify: `crates/core/Cargo.toml`
- Modify: `crates/server/Cargo.toml`

- [ ] **Step 1: Add deps**

In `crates/core/Cargo.toml`, append to `[dependencies]`:
```toml
getrandom = "0.2"
```

In `crates/server/Cargo.toml`, append to `[dependencies]`:
```toml
serde_json = "1"
```

- [ ] **Step 2: Verify compilation**

```bash
cargo build -p gamenet-core -p server
```

Expected: success (crates download and compile).

- [ ] **Step 3: Commit**

```bash
git add crates/core/Cargo.toml crates/server/Cargo.toml Cargo.lock
git commit -m "chore: add getrandom and serde_json deps"
```

---

### Task 3: Create `gamenet-core::identity` module

**Files:**
- Create: `crates/core/src/identity.rs`
- Modify: `crates/core/src/lib.rs`

- [ ] **Step 1: Write the failing tests**

Create `crates/core/src/identity.rs` with tests only (no implementation yet):

```rust
pub type TunnelToken = [u8; 32];

fn identity_path() -> std::path::PathBuf {
    todo!()
}

pub fn load_or_create() -> anyhow::Result<TunnelToken> {
    load_or_create_at(&identity_path())
}

pub fn load_or_create_at(path: &std::path::Path) -> anyhow::Result<TunnelToken> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(suffix: &str) -> std::path::PathBuf {
        let ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        std::env::temp_dir().join(format!("gamenet-id-{}-{}.bin", suffix, ns))
    }

    #[test]
    fn creates_token_on_fresh_path() {
        let path = temp_path("fresh");
        let token = load_or_create_at(&path).unwrap();
        assert_eq!(token.len(), 32);
        assert!(path.exists());
    }

    #[test]
    fn loads_same_token_on_second_call() {
        let path = temp_path("reload");
        let token1 = load_or_create_at(&path).unwrap();
        let token2 = load_or_create_at(&path).unwrap();
        assert_eq!(token1, token2);
    }

    #[test]
    fn tokens_are_not_all_zeros() {
        let path = temp_path("nonzero");
        let token = load_or_create_at(&path).unwrap();
        assert_ne!(token, [0u8; 32]);
    }
}
```

- [ ] **Step 2: Export the module in `lib.rs`**

Replace `crates/core/src/lib.rs`:

```rust
pub mod identity;
pub mod message;
pub mod presets;
pub mod protocol;
pub mod crypto;
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
cargo test -p gamenet-core identity
```

Expected: FAIL with panics from `todo!()`.

- [ ] **Step 4: Implement `identity.rs`**

Replace the full `crates/core/src/identity.rs`:

```rust
use std::path::{Path, PathBuf};

pub type TunnelToken = [u8; 32];

fn identity_path() -> PathBuf {
    let base = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    base.join(".config").join("gamenet").join("identity.bin")
}

pub fn load_or_create() -> anyhow::Result<TunnelToken> {
    load_or_create_at(&identity_path())
}

pub fn load_or_create_at(path: &Path) -> anyhow::Result<TunnelToken> {
    if path.exists() {
        let bytes = std::fs::read(path)?;
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Identity file corrupt: expected 32 bytes at {:?}", path))
    } else {
        let mut token = [0u8; 32];
        getrandom::getrandom(&mut token)
            .map_err(|e| anyhow::anyhow!("Failed to generate token: {}", e))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, &token)?;
        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(suffix: &str) -> PathBuf {
        let ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        std::env::temp_dir().join(format!("gamenet-id-{}-{}.bin", suffix, ns))
    }

    #[test]
    fn creates_token_on_fresh_path() {
        let path = temp_path("fresh");
        let token = load_or_create_at(&path).unwrap();
        assert_eq!(token.len(), 32);
        assert!(path.exists());
    }

    #[test]
    fn loads_same_token_on_second_call() {
        let path = temp_path("reload");
        let token1 = load_or_create_at(&path).unwrap();
        let token2 = load_or_create_at(&path).unwrap();
        assert_eq!(token1, token2);
    }

    #[test]
    fn tokens_are_not_all_zeros() {
        let path = temp_path("nonzero");
        let token = load_or_create_at(&path).unwrap();
        assert_ne!(token, [0u8; 32]);
    }
}
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cargo test -p gamenet-core identity
```

Expected: 3 PASS

- [ ] **Step 6: Commit**

```bash
git add crates/core/src/identity.rs crates/core/src/lib.rs
git commit -m "feat: add stable tunnel identity (generate/persist 32-byte token)"
```

---

### Task 4: Add `token` field to `ControlMessage::Register`

**Files:**
- Modify: `crates/core/src/protocol.rs`

This task is a mechanical change — adding the field and fixing the two call sites that construct `Register` so the project still compiles. The call sites are updated properly in Tasks 6 and 8; here we just make it build.

- [ ] **Step 1: Update the protocol**

Replace `crates/core/src/protocol.rs`:

```rust
use serde::{Deserialize, Serialize};
use crate::identity::TunnelToken;

/// Control messages sent over the control stream.
///
/// Serialized with bincode and framed with a 4-byte length prefix
/// (see [`crate::message`] for the send/recv helpers).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ControlMessage {
    /// Agent -> Server: "I want to host a game"
    Register {
        protocol: Protocol,
        local_port: u16,
        /// Stable 32-byte identity token that determines which public port this agent gets.
        token: TunnelToken,
    },
    /// Server -> Agent: "Your tunnel is live, players connect here"
    TunnelReady { public_port: u16 },
    /// Server -> Agent: "A new player connected" (sent over control stream)
    NewConnection { stream_id: u64 },
    /// Either direction: something went wrong
    Error { message: String },
}

/// Supported transport protocols.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}
```

- [ ] **Step 2: Fix call sites so the workspace compiles**

In `crates/cli/src/tunnel.rs`, find the `Register` construction (around line 72) and add a placeholder token. We replace it properly in Task 8:

```rust
// Temporary placeholder — replaced with real identity in Task 8
send_msg(
    &mut ctrl_send,
    &ControlMessage::Register {
        protocol: Protocol::Tcp,
        local_port,
        token: [0u8; 32],
    },
)
.await?;
```

In `crates/server/src/tunnel.rs`, find the pattern match on `Register` (around line 38) and add the `token` binding:

```rust
let ControlMessage::Register { local_port, token, .. } = msg else {
    warn!("Expected Register, got {:?}", msg);
    anyhow::bail!("Invalid first message");
};
```

(The `token` variable is unused for now and will be used in Task 6.)

- [ ] **Step 3: Verify the workspace compiles**

```bash
cargo build
```

Expected: success (may warn about unused `token` variable — that is fine).

- [ ] **Step 4: Commit**

```bash
git add crates/core/src/protocol.rs crates/cli/src/tunnel.rs crates/server/src/tunnel.rs
git commit -m "feat: add token field to Register message (compile pass)"
```

---

### Task 5: Overhaul `ServerState` — token registry, port pool, IP limits, persistence

**Files:**
- Modify: `crates/server/src/state.rs`

- [ ] **Step 1: Write the failing tests**

Replace `crates/server/src/state.rs` with tests only (no new logic yet):

```rust
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use gamenet_core::identity::TunnelToken;
use serde::{Deserialize, Serialize};

pub const MAX_TUNNELS_PER_IP: usize = 5;
const PORT_RANGE_START: u16 = 10000;
const PORT_RANGE_END: u16 = 10999;

pub struct TunnelEntry {
    pub public_port: u16,
    pub local_port: u16,
    pub peer_ip: IpAddr,
}

pub struct ServerState {
    token_ports: HashMap<TunnelToken, u16>,
    active_tunnels: HashMap<u16, TunnelEntry>,
    free_ports: VecDeque<u16>,
    connections_per_ip: HashMap<IpAddr, usize>,
    state_path: PathBuf,
}

impl ServerState {
    pub fn new() -> Self {
        Self::new_with_path("./gamenet-state.json")
    }

    pub fn new_with_path(path: impl Into<PathBuf>) -> Self {
        todo!()
    }

    pub fn load_or_new(path: impl Into<PathBuf>) -> Self {
        todo!()
    }

    pub fn assign_or_resume(
        &mut self,
        token: TunnelToken,
        local_port: u16,
        peer_ip: IpAddr,
    ) -> anyhow::Result<u16> {
        todo!()
    }

    pub fn release(&mut self, public_port: u16) {
        todo!()
    }

    pub fn tunnel_count(&self) -> usize {
        self.active_tunnels.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(suffix: &str) -> PathBuf {
        let ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        std::env::temp_dir().join(format!("gamenet-state-{}-{}.json", suffix, ns))
    }

    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

    #[test]
    fn new_token_gets_a_port_in_range() {
        let mut state = ServerState::new_with_path(temp_path("range"));
        let port = state.assign_or_resume([1u8; 32], 25565, ip("1.2.3.4")).unwrap();
        assert!((PORT_RANGE_START..=PORT_RANGE_END).contains(&port));
    }

    #[test]
    fn same_token_gets_same_port_after_disconnect() {
        let mut state = ServerState::new_with_path(temp_path("same"));
        let port1 = state.assign_or_resume([2u8; 32], 25565, ip("1.2.3.4")).unwrap();
        state.release(port1);
        let port2 = state.assign_or_resume([2u8; 32], 25565, ip("1.2.3.4")).unwrap();
        assert_eq!(port1, port2);
    }

    #[test]
    fn different_tokens_get_different_ports() {
        let mut state = ServerState::new_with_path(temp_path("diff"));
        let p1 = state.assign_or_resume([3u8; 32], 25565, ip("1.2.3.4")).unwrap();
        let p2 = state.assign_or_resume([4u8; 32], 25565, ip("1.2.3.4")).unwrap();
        assert_ne!(p1, p2);
    }

    #[test]
    fn ip_limit_is_enforced() {
        let mut state = ServerState::new_with_path(temp_path("iplimit"));
        let attacker = ip("1.2.3.4");
        for i in 0..MAX_TUNNELS_PER_IP {
            let mut token = [0u8; 32];
            token[0] = i as u8;
            state.assign_or_resume(token, 25565, attacker).unwrap();
        }
        let mut extra_token = [0u8; 32];
        extra_token[0] = 99;
        let result = state.assign_or_resume(extra_token, 25565, attacker);
        assert!(result.is_err());
    }

    #[test]
    fn release_frees_ip_slot() {
        let mut state = ServerState::new_with_path(temp_path("release"));
        let my_ip = ip("5.5.5.5");
        let mut token = [0u8; 32];
        for i in 0..MAX_TUNNELS_PER_IP {
            token[0] = i as u8;
            state.assign_or_resume(token, 25565, my_ip).unwrap();
        }
        // At limit — release one
        token[0] = 0;
        let port = state.assign_or_resume(token, 25565, my_ip).unwrap(); // same port, already counted
        state.release(port);
        // Now a new token should succeed
        token[0] = 100;
        assert!(state.assign_or_resume(token, 25565, my_ip).is_ok());
    }

    #[test]
    fn save_and_load_preserves_token_port_mapping() {
        let path = temp_path("persist");
        let token = [42u8; 32];
        let port = {
            let mut state = ServerState::new_with_path(&path);
            state.assign_or_resume(token, 25565, ip("1.2.3.4")).unwrap()
        };
        // Load fresh state from same file
        let mut loaded = ServerState::load_or_new(&path);
        let port2 = loaded.assign_or_resume(token, 25565, ip("2.3.4.5")).unwrap();
        assert_eq!(port, port2);
        std::fs::remove_file(&path).ok();
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p server
```

Expected: FAIL (panics from `todo!()`).

- [ ] **Step 3: Implement the full `ServerState`**

Replace the full `crates/server/src/state.rs`:

```rust
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use gamenet_core::identity::TunnelToken;
use serde::{Deserialize, Serialize};
use tracing::warn;

pub const MAX_TUNNELS_PER_IP: usize = 5;
const PORT_RANGE_START: u16 = 10000;
const PORT_RANGE_END: u16 = 10999;

pub struct TunnelEntry {
    pub public_port: u16,
    pub local_port: u16,
    pub peer_ip: IpAddr,
}

pub struct ServerState {
    // Permanent: token → reserved port (written to disk on every change)
    token_ports: HashMap<TunnelToken, u16>,
    // Transient: populated only while an agent is connected
    active_tunnels: HashMap<u16, TunnelEntry>,
    // Ports not yet assigned to any token
    free_ports: VecDeque<u16>,
    connections_per_ip: HashMap<IpAddr, usize>,
    state_path: PathBuf,
}

// ── Persistence ─────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct PersistedState {
    // hex-encoded token → assigned port
    token_ports: Vec<(String, u16)>,
}

fn token_to_hex(token: &TunnelToken) -> String {
    token.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_to_token(s: &str) -> anyhow::Result<TunnelToken> {
    anyhow::ensure!(s.len() == 64, "Token hex must be 64 chars, got {}", s.len());
    let bytes: Vec<u8> = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow::anyhow!("{}", e)))
        .collect::<anyhow::Result<_>>()?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Wrong token byte count"))
}

// ── Construction ─────────────────────────────────────────────────────────────

impl ServerState {
    pub fn new() -> Self {
        Self::new_with_path("./gamenet-state.json")
    }

    pub fn new_with_path(path: impl Into<PathBuf>) -> Self {
        let free_ports = (PORT_RANGE_START..=PORT_RANGE_END).collect();
        Self {
            token_ports: HashMap::new(),
            active_tunnels: HashMap::new(),
            free_ports,
            connections_per_ip: HashMap::new(),
            state_path: path.into(),
        }
    }

    /// Load from disk if the file exists; otherwise start fresh.
    pub fn load_or_new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        match Self::load(&path) {
            Ok(s) => s,
            Err(e) => {
                if path.exists() {
                    warn!("Failed to load state from {:?}: {} — starting fresh", path, e);
                }
                Self::new_with_path(path)
            }
        }
    }

    fn load(path: &Path) -> anyhow::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        let persisted: PersistedState = serde_json::from_str(&json)?;

        let mut state = Self::new_with_path(path);
        for (hex, port) in persisted.token_ports {
            let token = hex_to_token(&hex)?;
            state.token_ports.insert(token, port);
            state.free_ports.retain(|&p| p != port);
        }
        Ok(state)
    }

    fn save(&self) {
        let persisted = PersistedState {
            token_ports: self
                .token_ports
                .iter()
                .map(|(k, &v)| (token_to_hex(k), v))
                .collect(),
        };
        match serde_json::to_string_pretty(&persisted) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&self.state_path, json) {
                    warn!("Failed to persist state to {:?}: {}", self.state_path, e);
                }
            }
            Err(e) => warn!("Failed to serialize state: {}", e),
        }
    }
}

// ── Mutations ────────────────────────────────────────────────────────────────

impl ServerState {
    /// Assign or resume a port for the given token.
    ///
    /// Returns Err if the IP has too many active tunnels or the port pool is full.
    pub fn assign_or_resume(
        &mut self,
        token: TunnelToken,
        local_port: u16,
        peer_ip: IpAddr,
    ) -> anyhow::Result<u16> {
        let count = self.connections_per_ip.get(&peer_ip).copied().unwrap_or(0);
        anyhow::ensure!(
            count < MAX_TUNNELS_PER_IP,
            "Too many tunnels from {} (max {})",
            peer_ip,
            MAX_TUNNELS_PER_IP
        );

        let port = if let Some(&existing) = self.token_ports.get(&token) {
            existing
        } else {
            let p = self
                .free_ports
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("Port pool exhausted (max 1 000 tunnels)"))?;
            self.token_ports.insert(token, p);
            self.save(); // Persist new token→port mapping immediately
            p
        };

        self.active_tunnels.insert(
            port,
            TunnelEntry { public_port: port, local_port, peer_ip },
        );
        *self.connections_per_ip.entry(peer_ip).or_insert(0) += 1;
        Ok(port)
    }

    /// Mark a tunnel as disconnected. Port stays reserved for the token.
    pub fn release(&mut self, public_port: u16) {
        if let Some(entry) = self.active_tunnels.remove(&public_port) {
            let count = self.connections_per_ip.entry(entry.peer_ip).or_insert(0);
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.connections_per_ip.remove(&entry.peer_ip);
            }
        }
        // token_ports intentionally NOT cleared — port is permanently reserved
    }

    pub fn tunnel_count(&self) -> usize {
        self.active_tunnels.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(suffix: &str) -> PathBuf {
        let ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        std::env::temp_dir().join(format!("gamenet-state-{}-{}.json", suffix, ns))
    }

    fn ip(s: &str) -> IpAddr { s.parse().unwrap() }

    #[test]
    fn new_token_gets_a_port_in_range() {
        let mut state = ServerState::new_with_path(temp_path("range"));
        let port = state.assign_or_resume([1u8; 32], 25565, ip("1.2.3.4")).unwrap();
        assert!((PORT_RANGE_START..=PORT_RANGE_END).contains(&port));
    }

    #[test]
    fn same_token_gets_same_port_after_disconnect() {
        let mut state = ServerState::new_with_path(temp_path("same"));
        let port1 = state.assign_or_resume([2u8; 32], 25565, ip("1.2.3.4")).unwrap();
        state.release(port1);
        let port2 = state.assign_or_resume([2u8; 32], 25565, ip("1.2.3.4")).unwrap();
        assert_eq!(port1, port2);
    }

    #[test]
    fn different_tokens_get_different_ports() {
        let mut state = ServerState::new_with_path(temp_path("diff"));
        let p1 = state.assign_or_resume([3u8; 32], 25565, ip("1.2.3.4")).unwrap();
        let p2 = state.assign_or_resume([4u8; 32], 25565, ip("1.2.3.4")).unwrap();
        assert_ne!(p1, p2);
    }

    #[test]
    fn ip_limit_is_enforced() {
        let mut state = ServerState::new_with_path(temp_path("iplimit"));
        let attacker = ip("1.2.3.4");
        for i in 0..MAX_TUNNELS_PER_IP {
            let mut token = [0u8; 32];
            token[0] = i as u8;
            state.assign_or_resume(token, 25565, attacker).unwrap();
        }
        let mut extra_token = [0u8; 32];
        extra_token[0] = 99;
        assert!(state.assign_or_resume(extra_token, 25565, attacker).is_err());
    }

    #[test]
    fn release_frees_ip_slot() {
        let mut state = ServerState::new_with_path(temp_path("release"));
        let my_ip = ip("5.5.5.5");
        let mut tokens: Vec<u16> = vec![];
        for i in 0..MAX_TUNNELS_PER_IP {
            let mut token = [0u8; 32];
            token[0] = i as u8;
            tokens.push(state.assign_or_resume(token, 25565, my_ip).unwrap());
        }
        state.release(tokens[0]);
        let mut new_token = [0u8; 32];
        new_token[0] = 100;
        assert!(state.assign_or_resume(new_token, 25565, my_ip).is_ok());
    }

    #[test]
    fn save_and_load_preserves_token_port_mapping() {
        let path = temp_path("persist");
        let token = [42u8; 32];
        let port = {
            let mut state = ServerState::new_with_path(&path);
            state.assign_or_resume(token, 25565, ip("1.2.3.4")).unwrap()
        };
        let mut loaded = ServerState::load_or_new(&path);
        let port2 = loaded.assign_or_resume(token, 25565, ip("2.3.4.5")).unwrap();
        assert_eq!(port, port2);
        std::fs::remove_file(&path).ok();
    }
}
```

- [ ] **Step 4: Update `RelayServer::bind` to load persisted state**

In `crates/server/src/relay.rs`, change the state initialisation inside `bind`:

```rust
use crate::state::ServerState;

pub async fn bind(addr: &str) -> anyhow::Result<Self> {
    let (server_config, _cert) = gamenet_core::crypto::server_config()?;
    let endpoint = Endpoint::server(server_config, addr.parse()?)?;
    info!("QUIC relay server listening on {}", addr);
    let state = ServerState::load_or_new("./gamenet-state.json");
    Ok(Self {
        state: Arc::new(Mutex::new(state)),
        endpoint,
    })
}
```

- [ ] **Step 5: Run the server tests**

```bash
cargo test -p server
```

Expected: all state tests PASS

- [ ] **Step 6: Commit**

```bash
git add crates/server/src/state.rs crates/server/src/relay.rs
git commit -m "feat: token-keyed port pool, IP rate limit, persistent state"
```

---

### Task 6: Update `Tunnel` — use token from Register, add peer IP, add player cap

**Files:**
- Modify: `crates/server/src/tunnel.rs`

- [ ] **Step 1: Write the failing test**

Append inside `crates/server/src/tunnel.rs` (before the closing brace of the file, or add a new `#[cfg(test)]` block):

```rust
#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn player_counter_saturates_at_max() {
        let counter = Arc::new(AtomicUsize::new(0));
        let max = 50usize;

        // Simulate 50 players joining
        for _ in 0..max {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(counter.load(Ordering::Relaxed), max);

        // 51st player should be rejected: counter is at max
        let current = counter.fetch_add(1, Ordering::Relaxed);
        assert!(current >= max, "player should have been rejected at or above max");
        // Revert the phantom increment
        counter.fetch_sub(1, Ordering::Relaxed);
        assert_eq!(counter.load(Ordering::Relaxed), max);
    }
}
```

- [ ] **Step 2: Run test to verify it passes already (pure logic test)**

```bash
cargo test -p server player_counter
```

Expected: PASS — this validates the atomic logic pattern before we wire it in.

- [ ] **Step 3: Replace `tunnel.rs` with the new implementation**

Replace the full `crates/server/src/tunnel.rs`:

```rust
use crate::bridge;
use crate::state::ServerState;
use gamenet_core::message::{recv_msg, send_msg};
use gamenet_core::protocol::ControlMessage;
use quinn::{Connection, SendStream};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

const MAX_CONCURRENT_PLAYERS: usize = 50;

/// One active tunnel between an agent and its players.
pub struct Tunnel {
    quic: Connection,
    ctrl_send: SendStream,
    state: Arc<Mutex<ServerState>>,
    public_port: u16,
    local_port: u16,
    peer_ip: IpAddr,
    stream_counter: u64,
    active_players: Arc<AtomicUsize>,
}

impl Tunnel {
    /// Perform the handshake over the first QUIC bi-stream.
    pub async fn from_quic(
        conn: Connection,
        state: Arc<Mutex<ServerState>>,
        peer_ip: IpAddr,
    ) -> anyhow::Result<Self> {
        let (mut ctrl_send, mut ctrl_recv) = conn.accept_bi().await?;

        let msg = recv_msg(&mut ctrl_recv)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Agent disconnected before registering"))?;

        let ControlMessage::Register { local_port, token, .. } = msg else {
            warn!("Expected Register, got {:?}", msg);
            anyhow::bail!("Invalid first message");
        };

        let public_port = state
            .lock()
            .await
            .assign_or_resume(token, local_port, peer_ip)?;

        send_msg(&mut ctrl_send, &ControlMessage::TunnelReady { public_port }).await?;
        info!(
            "Tunnel registered: public :{} -> agent :{}",
            public_port, local_port
        );

        Ok(Self {
            quic: conn,
            ctrl_send,
            state,
            public_port,
            local_port,
            peer_ip,
            stream_counter: 0,
            active_players: Arc::new(AtomicUsize::new(0)),
        })
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.public_port)).await?;
        info!("Tunnel LIVE  :{} -> agent :{}", self.public_port, self.local_port);

        loop {
            let (player, addr) = listener.accept().await?;

            // Enforce per-tunnel player cap
            let current = self.active_players.fetch_add(1, Ordering::Relaxed);
            if current >= MAX_CONCURRENT_PLAYERS {
                self.active_players.fetch_sub(1, Ordering::Relaxed);
                warn!("Player {} rejected: tunnel at max {} concurrent players", addr, MAX_CONCURRENT_PLAYERS);
                drop(player);
                continue;
            }

            info!("Player {} connected ({}/{})", addr, current + 1, MAX_CONCURRENT_PLAYERS);

            self.stream_counter += 1;
            let stream_id = self.stream_counter;

            send_msg(
                &mut self.ctrl_send,
                &ControlMessage::NewConnection { stream_id },
            )
            .await?;

            let quic = self.quic.clone();
            let players = Arc::clone(&self.active_players);
            tokio::spawn(async move {
                match quic.open_bi().await {
                    Ok((quic_send, quic_recv)) => {
                        if let Err(e) =
                            bridge::bridge_tcp_to_quic(player, quic_send, quic_recv, addr).await
                        {
                            error!("Player {} bridge error: {}", addr, e);
                        }
                    }
                    Err(e) => {
                        error!("Failed to open QUIC stream for player {}: {}", addr, e);
                    }
                }
                players.fetch_sub(1, Ordering::Relaxed);
                info!("Player {} disconnected", addr);
            });
        }
    }

    pub async fn cleanup(&self) {
        self.state.lock().await.release(self.public_port);
        info!("Tunnel on port {} released (peer {})", self.public_port, self.peer_ip);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn player_counter_saturates_at_max() {
        let counter = Arc::new(AtomicUsize::new(0));
        let max = 50usize;
        for _ in 0..max {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(counter.load(Ordering::Relaxed), max);
        let current = counter.fetch_add(1, Ordering::Relaxed);
        assert!(current >= max);
        counter.fetch_sub(1, Ordering::Relaxed);
        assert_eq!(counter.load(Ordering::Relaxed), max);
    }
}
```

- [ ] **Step 4: Run the server tests**

```bash
cargo test -p server
```

Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add crates/server/src/tunnel.rs
git commit -m "feat: use token in registration, add 50-player cap per tunnel"
```

---

### Task 7: Pass `peer_ip` from `RelayServer` into `Tunnel::from_quic`

**Files:**
- Modify: `crates/server/src/relay.rs`

- [ ] **Step 1: Update `relay.rs`**

Replace the full `crates/server/src/relay.rs`:

```rust
use crate::state::ServerState;
use crate::tunnel::Tunnel;
use quinn::Endpoint;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

pub struct RelayServer {
    state: Arc<Mutex<ServerState>>,
    endpoint: Endpoint,
}

impl RelayServer {
    pub async fn bind(addr: &str) -> anyhow::Result<Self> {
        let (server_config, _cert) = gamenet_core::crypto::server_config()?;
        let endpoint = Endpoint::server(server_config, addr.parse()?)?;
        info!("QUIC relay server listening on {}", addr);
        let state = ServerState::load_or_new("./gamenet-state.json");
        Ok(Self {
            state: Arc::new(Mutex::new(state)),
            endpoint,
        })
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        while let Some(incoming) = self.endpoint.accept().await {
            let state = Arc::clone(&self.state);
            tokio::spawn(async move {
                let addr = incoming.remote_address();
                let peer_ip = addr.ip();

                let connecting = match incoming.accept() {
                    Ok(c) => c,
                    Err(e) => {
                        error!("Failed to accept incoming from {}: {}", addr, e);
                        return;
                    }
                };

                let connection = match connecting.into_0rtt() {
                    Ok((conn, _zero_rtt)) => {
                        info!("Agent connected from {} (QUIC 0.5-RTT)", addr);
                        conn
                    }
                    Err(connecting) => match connecting.await {
                        Ok(conn) => {
                            info!("Agent connected from {} (QUIC 1-RTT)", addr);
                            conn
                        }
                        Err(e) => {
                            error!("QUIC handshake failed from {}: {}", addr, e);
                            return;
                        }
                    },
                };

                match Tunnel::from_quic(connection, state, peer_ip).await {
                    Ok(mut tunnel) => {
                        if let Err(e) = tunnel.run().await {
                            error!("Agent {} tunnel error: {}", addr, e);
                        }
                        tunnel.cleanup().await;
                    }
                    Err(e) => {
                        warn!("Agent {} failed to register: {}", addr, e);
                    }
                }
            });
        }
        Ok(())
    }
}
```

- [ ] **Step 2: Build the full workspace**

```bash
cargo build
```

Expected: success with no errors.

- [ ] **Step 3: Run all server tests**

```bash
cargo test -p server
```

Expected: all PASS

- [ ] **Step 4: Commit**

```bash
git add crates/server/src/relay.rs
git commit -m "feat: thread peer IP through relay into tunnel registration"
```

---

### Task 8: CLI identity integration

**Files:**
- Modify: `crates/cli/src/tunnel.rs`
- Modify: `crates/cli/src/main.rs`

- [ ] **Step 1: Write the test**

Add a test to `crates/cli/src/tunnel.rs` that verifies the CLI loads an identity and that the identity doesn't change between calls:

```rust
#[cfg(test)]
mod tests {
    use gamenet_core::identity;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn identity_is_stable_across_calls() {
        let ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let path = std::env::temp_dir().join(format!("cli-id-{}.bin", ns));
        let t1 = identity::load_or_create_at(&path).unwrap();
        let t2 = identity::load_or_create_at(&path).unwrap();
        assert_eq!(t1, t2);
        std::fs::remove_file(&path).ok();
    }
}
```

- [ ] **Step 2: Run to verify it passes (identity already works)**

```bash
cargo test -p cli identity_is_stable
```

Expected: PASS

- [ ] **Step 3: Update `AgentTunnel::connect` to load and send the real token**

Replace the full `crates/cli/src/tunnel.rs`:

```rust
use crate::bridge;
use gamenet_core::crypto;
use gamenet_core::identity;
use gamenet_core::message::{recv_msg, send_msg};
use gamenet_core::protocol::{ControlMessage, Protocol};
use quinn::{Connection, Endpoint};
use tracing::{error, info};

pub struct AgentTunnel {
    quic: Connection,
    local_port: u16,
}

impl AgentTunnel {
    pub async fn connect(server_ip: &str, local_port: u16) -> anyhow::Result<Self> {
        let token = identity::load_or_create()?;

        let client_config = crypto::insecure_client_config()?;
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_config);

        let server_addr = format!("{}:5000", server_ip);
        let resolved: std::net::SocketAddr = match server_addr.parse() {
            Ok(addr) => addr,
            Err(_) => tokio::net::lookup_host(&server_addr)
                .await?
                .next()
                .ok_or_else(|| anyhow::anyhow!("Could not resolve {}", server_addr))?,
        };
        info!("Connecting to {}", resolved);

        let connecting = endpoint.connect(resolved, "localhost")?;
        let quic = match connecting.into_0rtt() {
            Ok((conn, zero_rtt_accepted)) => {
                info!("0-RTT connection attempt to {}", server_addr);
                tokio::spawn(async move {
                    if zero_rtt_accepted.await {
                        info!("Server accepted 0-RTT data");
                    } else {
                        info!("Server rejected 0-RTT (fell back to 1-RTT)");
                    }
                });
                conn
            }
            Err(connecting) => {
                info!("Full QUIC handshake to {}", server_addr);
                connecting.await?
            }
        };
        info!("QUIC connection established to {}", server_addr);

        let (mut ctrl_send, mut ctrl_recv) = quic.open_bi().await?;

        send_msg(
            &mut ctrl_send,
            &ControlMessage::Register {
                protocol: Protocol::Tcp,
                local_port,
                token,
            },
        )
        .await?;

        let msg = recv_msg(&mut ctrl_recv)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Server closed before confirming tunnel"))?;

        match msg {
            ControlMessage::TunnelReady { public_port } => {
                info!("===========================================");
                info!("  TUNNEL IS LIVE!");
                info!("  Tell players to connect to:");
                info!("    {}:{}", server_ip, public_port);
                info!("  (This port is permanently yours — share it once)");
                info!("===========================================");
            }
            ControlMessage::Error { message } => {
                anyhow::bail!("Server rejected registration: {}", message);
            }
            other => {
                anyhow::bail!("Unexpected response: {:?}", other);
            }
        }

        tokio::spawn(async move {
            if let Err(e) = Self::handle_control_messages(ctrl_recv).await {
                error!("Control channel error: {}", e);
            }
        });

        Ok(Self { quic, local_port })
    }

    async fn handle_control_messages(mut ctrl_recv: quinn::RecvStream) -> anyhow::Result<()> {
        loop {
            match recv_msg(&mut ctrl_recv).await? {
                Some(ControlMessage::NewConnection { stream_id }) => {
                    info!("Player #{} joined! Accepting QUIC stream...", stream_id);
                }
                Some(_) => {}
                None => {
                    info!("Control channel closed by server.");
                    break;
                }
            }
        }
        Ok(())
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            let (quic_send, quic_recv) = match self.quic.accept_bi().await {
                Ok(streams) => streams,
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    info!("Server closed the connection. Shutting down.");
                    break;
                }
                Err(e) => {
                    error!("QUIC stream accept error: {}", e);
                    break;
                }
            };

            let local_port = self.local_port;
            tokio::spawn(async move {
                if let Err(e) = bridge::bridge_to_local(quic_send, quic_recv, local_port).await {
                    error!("Bridge error: {}", e);
                }
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use gamenet_core::identity;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn identity_is_stable_across_calls() {
        let ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let path = std::env::temp_dir().join(format!("cli-id-{}.bin", ns));
        let t1 = identity::load_or_create_at(&path).unwrap();
        let t2 = identity::load_or_create_at(&path).unwrap();
        assert_eq!(t1, t2);
        std::fs::remove_file(&path).ok();
    }
}
```

- [ ] **Step 4: Fix the default `--server` value in `main.rs`**

In `crates/cli/src/main.rs`, change the `server` arg default from `""` to `"localhost"`:

```rust
/// Relay server address (for development/testing)
#[arg(long, default_value = "localhost", hide = true)]
server: String,
```

- [ ] **Step 5: Build and run all tests**

```bash
cargo build && cargo test
```

Expected: all tests PASS, no compilation errors.

- [ ] **Step 6: Smoke-test the binary help output**

```bash
cargo run -p cli -- --help
cargo run -p cli -- host --help
```

Expected: help text prints without errors; supported games listed.

- [ ] **Step 7: Commit**

```bash
git add crates/cli/src/tunnel.rs crates/cli/src/main.rs
git commit -m "feat: load stable identity token in CLI and send in Register"
```

---

## Self-review against the spec

| Requirement | Task |
|-------------|------|
| Same URL across sessions (stable port per identity) | Tasks 3, 4, 5 |
| Port assignment survives server restart | Task 5 (`save`/`load_or_new`) |
| Updated port system (capped pool, not unbounded counter) | Task 5 |
| OOM via oversized message | Task 1 |
| Port exhaustion attack | Task 5 (1 000-port cap) |
| Player flood attack | Task 6 (50-player cap) |
| Per-IP tunnel abuse | Task 5 (5 tunnels/IP) |
| `--server` default broken (empty string) | Task 8 |
| TLS cert verification | **Explicitly out of scope** |
| QUIC flood | **Explicitly out of scope** |
