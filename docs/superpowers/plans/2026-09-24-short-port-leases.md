# Short Port Leases Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace permanent token-to-port reservations with a five-minute reconnect lease while keeping public TCP tunnels easy to create and share.

**Architecture:** Keep a single lease table behind the existing server-state mutex. Bind a player's TCP listener and durably save the lease before confirming registration; identify each active connection with a session ID so old cleanup cannot affect a replacement. Store only token fingerprints and expiring leases in a versioned JSON file, with a one-time migration of existing reservations.

**Tech Stack:** Rust 2024, Tokio, Quinn 0.11, serde/serde_json, `ring` SHA-256, `tempfile` for same-directory atomic replacement.

**Spec:** [Short Port Leases design](../specs/2026-09-24-short-port-leases-design.md)

## Global Constraints

- TCP tunnels remain public: no accounts, permanent port option, or new player-facing protocol.
- One active connection per 32-byte token; reject a second live connection without disturbing the first.
- Port pool `10000..=10999`; five active **plus grace** leases per last IP.
- Clean disconnect grace is 300 seconds. Refresh active leases every 30 seconds with an expiry 300 seconds after refresh. Load every unexpired saved record as grace after restart.
- A running CLI retries lost relay connections after 1, 2, 4, 8, then at most 15 seconds, reusing its token and printing the resulting address.
- Cap pre-registration connections at 128 and give handshake plus first `Register` a 10-second application deadline.
- Limit players to 50 per tunnel and 2,000 across the relay. Keep each player counted until both copy directions complete or the bridge fails.
- Until UDP forwarding exists, reject `Protocol::Udp` and UDP-only presets explicitly; describe the product as TCP-only.
- The existing uncommitted dependency and test changes are in the working tree. Preserve them. Do not commit unless the user asks; this overrides the skill's commit step.
- Write a failing test, observe it fail, implement, and rerun for every behavioral change. Keep the state and persistence tests deterministic by passing explicit times.
- Security review is required for token handling, admission, persistent files, handshake timing, and migration. Do not log tokens or write raw tokens to the new file.

## Review Focus

1. A second connection with the same token while the first is active must receive an error; Task 1 tests the state rule and Task 3 tests the network response.
2. A port available in the lease table but occupied by another process must never be announced as ready; Task 3 binds before sending `TunnelReady` and tests bind failure.
3. A malformed or duplicated state file must stop startup without resetting leases; Task 2 tests each validation path.
4. A failed state write during registration or cleanup must not silently lose a lease; Tasks 2 and 3 test rejection, unhealthy-state admission, and retry.
5. A relay restart or late cleanup during a reconnect must preserve the new session and its port; Tasks 1 and 4 test both cases.
6. A player half-closing TCP must still receive the rest of the response, and that player must remain inside the cap until forwarding really ends; Task 5 tests both bridge directions and the global budget.
7. A relay restart while the host CLI remains open must lead to a new registration without requiring the host to rerun the command; Task 4 tests retry and address output.

---

## File map

- `crates/server/src/lease.rs`: pure lease transitions, quota, candidate ports, session-checked cleanup, explicit-time tests.
- `crates/server/src/state.rs`: a small `ServerState` wrapper that joins the table and store. Replace the old `token_ports`, `active_tunnels`, and `free_ports` fields when registration switches over in Task 3.
- `crates/server/src/lease_store.rs`: versioned JSON, validation, atomic writes, owner-only legacy backup, migration, storage tests.
- `crates/server/src/tunnel.rs`: register with a bound listener, own and stop player tasks, detect QUIC closure, conditional cleanup, socket-level tests.
- `crates/server/src/relay.rs`: fail-closed load, bounded registration, periodic refresh/retry, full-handshake registration.
- `crates/cli/src/tunnel.rs`: wait for full handshake and describe the address as reusable only during the reconnect window.
- `crates/server/src/bridge.rs` and `crates/cli/src/bridge.rs`: forward both TCP directions through completion with explicit half-close behavior.
- `crates/cli/src/main.rs` and `crates/core/src/presets.rs`: refuse UDP-only game presets until UDP exists.
- `crates/server/Cargo.toml`: direct `ring`, `tempfile`, and any test-only dependencies required by the socket tests; update `Cargo.lock` through Cargo.
- `README.md` and `ARCHITECTURE.md`: explain the reconnect promise, migration, state-file security, and operational limits where those files already discuss relay behavior.

### Task 1: Lease transitions and admission

**Files:** Create `crates/server/src/lease.rs` with focused inline tests; modify `crates/server/src/main.rs` to declare `mod lease`; add `ring` to `crates/server/Cargo.toml` and update `Cargo.lock`. Leave the existing `ServerState` in use until Task 3.

**Interfaces:** Define `TokenId([u8; 32])` from `ring::digest::SHA256` of `TunnelToken`; `SessionId(u64)` local to the process; `Lease { token_id, port, last_ip: Option<IpAddr>, state: Active { session_id, peer_ip } | Grace { expires_at_ms } }`; and `LeaseTable`. Export `candidate_ports(&mut self, token_id, peer_ip, now_ms) -> Result<Vec<u16>>`, `activate(&mut self, token_id, peer_ip, port, now_ms) -> Result<SessionId>`, `end(&mut self, token_id, session_id, now_ms) -> bool`, `reap_expired(&mut self, now_ms)`, `snapshot(&self, now_ms) -> Vec<LeaseRecord>`, `restore(records, now_ms) -> Result<Self>`, plus read-only `active_session` and `grace_port` helpers for tests. `LeaseRecord` contains token ID, port, optional last IP, and expiry. A reconnect candidate is only its saved port; a new token may try every unleased port in range. No filesystem work belongs here.

- [ ] **Write failing explicit-time tests** for new allocation, grace reclaim at 299 seconds, expiry at 300 seconds, duplicate active token, five active-plus-grace leases per IP, quota transfer on new-IP reconnect, and stale-session cleanup. Use a pattern like:

  ```rust
  let token = TokenId::from_token(&[7; 32]);
  let mut table = LeaseTable::new();
  let ip = "192.0.2.1".parse().unwrap();
  let port = table.candidate_ports(token, ip, 1_000).unwrap()[0];
  let old = table.activate(token, ip, port, 1_000).unwrap();
  assert!(table.end(token, old, 1_000));
  assert_eq!(table.candidate_ports(token, ip, 300_999).unwrap(), vec![port]);
  let new = table.activate(token, ip, port, 300_999).unwrap();
  assert!(!table.end(token, old, 301_000));
  assert_eq!(table.active_session(token), Some(new));
  ```

- [ ] **Run:** `cargo test -p server lease:: --locked`. **Expected:** compile or assertion failure for the missing lease API and new behavior.
- [ ] **Implement the table** with one token-keyed map and a port occupancy set; assign a fresh monotonic session ID on activation. Count both active and unexpired grace leases for the last IP, and remove expired grace before every admission check. Keep all time calculations checked. The essential transition is:

  ```rust
  // Only the current connection can move its lease into grace.
  if lease.active_session() != Some(session_id) { return false; }
  lease.state = Grace { expires_at_ms: now_ms.saturating_add(300_000) };
  true
  ```

- [ ] **Run:** `cargo test -p server lease:: --locked`. **Expected:** the new transition tests pass and the existing server still compiles. Review that tokens never appear in `Debug` or logs.

### Task 2: Durable lease store and one-time migration

**Files:** Create `crates/server/src/lease_store.rs`; modify `crates/server/src/main.rs` to declare `mod lease_store`, `crates/server/Cargo.toml`, and `Cargo.lock`. Put filesystem tests beside `lease_store.rs` using `tempfile::TempDir`. Leave relay startup unchanged until Task 3.

**Interfaces:** `LeaseStore::load_or_create(path: &Path, now_ms: u64) -> Result<(LeaseStore, LeaseTable)>`; `LeaseStore::save(&self, records: &[LeaseRecord]) -> Result<()>`. The v2 JSON root has `version: 2` and `leases: [{token_id: 64 lowercase hex chars, port, last_ip: null|string, expires_at_ms}]`. `load_or_create` returns an empty table only when the path does not exist. It validates a maximum 1 MiB input, known version, hex length and encoding, range, unique IDs and ports, and bounded record count; expired records are removed on load. Legacy `{ "token_ports": [[hex_token, port], ...] }` is validated before any change, backed up to an owner-only `gamenet-state.json.legacy-backup`, converted to grace expiring at `now_ms + 300_000`, and saved as v2. If the backup already exists and matches the source, reuse it; if it is a prefix left by an interrupted write, finish it atomically. Reject a conflicting backup.

- [ ] **Write failing tests** for missing-file creation, v2 round-trip with no raw token, expired-record removal, duplicate token and port, out-of-range port, unknown version, malformed/truncated JSON, oversized input, migration of two legacy reservations, and failure to save to an unwritable/missing parent. The key assertion is:

  ```rust
  let (store, table) = LeaseStore::load_or_create(&path, 1_000).unwrap();
  store.save(&table.snapshot(1_000)).unwrap();
  let bytes = std::fs::read(&path).unwrap();
  assert!(!bytes.windows(64).any(|w| w == legacy_raw_token_hex.as_bytes()));
  assert_eq!(LeaseStore::load_or_create(&path, 1_001).unwrap().1.grace_port(token), Some(port));
  ```

- [ ] **Run:** `cargo test -p server lease_store:: --locked`. **Expected:** compile failure for the absent module or failing assertions.
- [ ] **Implement strict load and save.** Create the replacement file in the same directory with owner-only permissions on Unix, write JSON, call `sync_all` on it, persist/rename, then sync the parent directory on Unix. On other platforms use the safest available atomic replacement and document any durability limit. Back up legacy bytes with owner-only permissions and `sync_all` before changing the original. Do not log token material or silently fall back to empty state. The startup call must use `?`:

  ```rust
  let (store, table) = LeaseStore::load_or_create(Path::new("./gamenet-state.json"), now_ms)?;
  ```

- [ ] **Run:** `cargo test -p server lease_store:: --locked` and `cargo test -p server lease:: --locked`. **Expected:** both pass and the existing server still compiles. Verify the backup and v2 permissions on Unix in a test, and inspect error paths for partial files.

### Task 3: Registration is a bound, persisted session

**Files:** Replace the old registry in `crates/server/src/state.rs`; modify `crates/server/src/tunnel.rs` and `crates/server/src/relay.rs`; add focused local-socket tests in `crates/server/src/tunnel.rs` or `crates/server/tests/registration.rs`.

**Interfaces:** Define `ServerState { leases: LeaseTable, store: LeaseStore, persistence_healthy: bool }` in `state.rs` with `ServerState::load_or_new(path: &Path, now_ms: u64) -> Result<Self>`; its fields are `pub(crate)` for the registration transaction. Add testable `RelayServer::bind_with_state_path(addr: &str, state_path: &Path) -> Result<Self>` and make `bind` call it with `./gamenet-state.json`. `Tunnel::from_quic` reads `Register` before locking shared state. For each candidate port it binds `TcpListener`; while still holding the state mutex it stages `activate`, persists `snapshot`, then commits the in-memory table. The returned `Tunnel` owns the bound listener, token ID, session ID, and a `tokio::task::JoinSet` of player forwarding tasks. `TunnelReady` is sent only after binding and saving. On a failed save, drop the listener and return an error; on a failed `TunnelReady` send, conditionally end and persist that session. If an `end` save fails, keep the in-memory grace transition, mark persistence unhealthy, and reject new registrations until a retry succeeds.

- [ ] **Write failing local QUIC/TCP tests** for duplicate token rejection without displacing the first, occupied reconnect port, new-token scan past an externally occupied port, no `TunnelReady` on save failure, idle QUIC disconnect closing the player listener, and stale cleanup leaving a replacement session active. Assert that a successful `TunnelReady` port accepts a TCP connect immediately:

  ```rust
  let ready_port = register_agent(&relay, token).await.unwrap();
  tokio::net::TcpStream::connect(("127.0.0.1", ready_port)).await.unwrap();
  assert!(register_agent(&relay, token).await.is_err());
  ```

- [ ] **Run:** `cargo test -p server registration --locked`. **Expected:** the new socket tests fail against the old register-before-bind behavior.
- [ ] **Implement registration as one transaction** under the state mutex. The guard may span the short local `TcpListener::bind().await` and synchronous file save, but must be dropped before sending control messages or forwarding traffic. For a new token, retry only candidate ports whose bind fails with address-in-use; for a grace reclaim, report that its saved port is unavailable without giving it away. Use a staged table clone or explicit rollback so a failed save cannot leave a live in-memory allocation.
- [ ] **Make `run` stop on QUIC closure** with `tokio::select!` between `conn.closed()` and `listener.accept()`. On exit, close the listener, abort and drain player tasks, then call session-checked cleanup. Also clean up if registration fails after activation. A narrow sketch of the shutdown branch:

  ```rust
  tokio::select! {
      _ = self.quic.closed() => break,
      accepted = self.listener.accept() => { /* existing player handling */ }
  }
  self.players.abort_all();
  while self.players.join_next().await.is_some() {}
  ```

- [ ] **Run:** `cargo test -p server registration --locked` and `cargo test -p server --locked`. **Expected:** socket tests and existing server tests pass. Inspect every `from_quic` error path for listener and lease cleanup.

### Task 4: Restart recovery, refresh, and handshake timing

**Files:** Modify `crates/server/src/relay.rs`, `crates/cli/src/tunnel.rs`, `crates/cli/src/main.rs`, `crates/server/src/tunnel.rs`, `README.md`, and `ARCHITECTURE.md` where present. Add runtime tests in `crates/server/tests/lease_lifecycle.rs` or adjacent module tests and CLI retry tests beside `crates/cli/src/tunnel.rs`.

**Interfaces:** The relay gets `ServerState::refresh_and_save(now_ms: u64) -> Result<()>`. Every 30 seconds it reaps expired grace and saves active records with expiry `now_ms + 300_000`; a successful save clears the unhealthy flag. On startup the store restores every unexpired record as grace. Both sides await the normal Quinn `Connecting` future before registration; neither uses `into_0rtt`. Apply a 10-second application timeout to handshake plus first `Register` and cap concurrent pre-registration tasks with a semaphore of 128 permits, releasing a permit after successful registration or failure. The CLI host loop reuses the identity token across attempts, retries after disconnect with a capped backoff of 1, 2, 4, 8, then 15 seconds, and logs the public address after every success.

- [ ] **Write failing runtime tests** for clean disconnect and same-token reconnect within 300 seconds, grace expiry and reuse by a different token, startup recovery from a saved active lease, failed-refresh recovery rejecting new admissions until a successful retry, registration timeout, and 129th pending connection being refused or held outside the task cap. Add a CLI test with a local relay that closes after registration, restarts, and observes the same token and port on automatic reconnect. Use an injected clock for lease decisions and Tokio paused time for interval/timeout tests. The restart assertion should be:

  ```rust
  let port = first_registration.public_port;
  drop(first_relay);
  let second_relay = RelayServer::bind_with_state_path(addr, &state_path).await.unwrap();
  assert_eq!(register_agent(&second_relay, token).await.unwrap(), port);
  ```

- [ ] **Run:** `cargo test -p server lease_lifecycle --locked`. **Expected:** tests fail against the old permanent reservations or missing runtime controls.
- [ ] **Implement the refresh loop and admission health flag.** Use a single interval task owned by the relay; do not create a task per lease. Persist the refreshed snapshot before treating storage as healthy. Ensure all loaded records become grace and that clean shutdown is not required for crash recovery.
- [ ] **Complete the full handshake before reading or sending `Register`** on server and CLI. Bound the server's pending connection work with `tokio::time::timeout(Duration::from_secs(10), ...)` and a 128-permit semaphore acquired before spawning; do not let an incomplete client hold a task indefinitely. Make the CLI host loop retry lost connections with 1, 2, 4, 8, then 15-second delays while it remains open, and display the new public address after each registration. Update CLI text to say the port is retained only for a five-minute reconnect window, and document the 300-second behavior and legacy backup removal.
- [ ] **Run:** `cargo test --workspace --locked`, `cargo clippy --workspace --all-targets --locked`, and `git diff --check`. **Expected:** all tests pass; compare Clippy output with any pre-existing warnings from the dependency/test update. Run `cargo fmt --all --check` and, if pre-existing formatting elsewhere fails, format only touched Rust files and note the baseline difference.

### Task 5: TCP forwarding and honest protocol support

**Files:** Modify `crates/server/src/bridge.rs`, `crates/cli/src/bridge.rs`, `crates/server/src/tunnel.rs`, `crates/server/src/relay.rs`, `crates/cli/src/main.rs`, `crates/core/src/presets.rs`, `README.md`, and `ARCHITECTURE.md`; add bridge tests beside each bridge or in `crates/server/tests/bridge.rs` and CLI tests beside `main.rs`.

**Interfaces:** Each bridge uses two in-scope copy futures rather than detached copy tasks. After `copy` reaches EOF in one direction, call `AsyncWriteExt::shutdown` on that direction's writer, then await the other direction; on an error, return it and cancel the sibling by dropping both futures. The relay owns `Arc<Semaphore>` with 2,000 permits and passes it to each tunnel. A player task owns one permit until its bridge ends; retain the 50-per-tunnel limit. Registration checks `protocol == Protocol::Tcp` before allocating or binding. CLI preset resolution rejects a preset whose protocol is UDP, even when `--port` overrides its default port.

- [ ] **Write failing bridge tests** with local TCP pairs and QUIC streams: client half-closes its write side after a request, game server sends a response, and the full response reaches the client; repeat with the game server half-closing first. Verify a bridge task is still live and its player permit remains held while the opposite direction is open. Verify both sides exit and release permits after EOF or error.
- [ ] **Run:** `cargo test -p server bridge --locked` and `cargo test -p cli bridge --locked`. **Expected:** the new half-close/ownership assertions fail with detached copy tasks.
- [ ] **Replace both bridge `tokio::spawn` plus `select!` blocks** with scoped directional futures and `tokio::try_join!`, explicitly shutting down each writer after EOF. A representative directional body is:

  ```rust
  let to_quic = async {
      tokio::io::copy(&mut tcp_read, &mut quic_send).await?;
      tokio::io::AsyncWriteExt::shutdown(&mut quic_send).await?;
      Ok::<(), anyhow::Error>(())
  };
  let to_tcp = async {
      tokio::io::copy(&mut quic_recv, &mut tcp_write).await?;
      tokio::io::AsyncWriteExt::shutdown(&mut tcp_write).await?;
      Ok::<(), anyhow::Error>(())
  };
  tokio::try_join!(to_quic, to_tcp)?;
  ```

- [ ] **Write failing admission tests** using an injected two-permit budget: the third concurrent player is rejected, a bridge that is still draining holds its permit, and the permit is released when both directions end. Write a CLI test that `bedrock`, `valheim`, or `factorio` returns an unsupported-UDP error; write a relay test that `Register { protocol: Protocol::Udp, .. }` is rejected without a lease.
- [ ] **Run:** `cargo test -p server player_limit --locked` and `cargo test -p cli udp_preset --locked`. **Expected:** these tests fail before the cap and validation exist.
- [ ] **Implement the shared semaphore and protocol checks.** Acquire a global permit before starting a player bridge, keep it in that task until the bridge returns, and release the per-tunnel count at the same point. Keep UDP presets in the data only if listing them clearly marks them unsupported; otherwise omit them from supported-game help. Change README's “TCP and UDP” claim to TCP-only.
- [ ] **Run:** `cargo test --workspace --locked`, `cargo clippy --workspace --all-targets --locked`, and `git diff --check`. **Expected:** all new and existing tests pass; inspect the whole bridge task tree for orphaned copy tasks.

## Final security review and handoff

- [ ] Trace a token from CLI storage to registration and disk; confirm no bearer token appears in v2 JSON, logs, errors, or test artifacts. Confirm the legacy backup stays owner-only and operators are told when to remove it.
- [ ] Trace each failure path: bind, save, `TunnelReady` send, QUIC close, forwarding error, refresh failure, restart. Confirm a port is announced only after its listener and durable lease exist, a previous session cannot clean up a newer one, and each accepted player owns exactly one global permit until forwarding ends.
- [ ] Check the complete diff, including the existing uncommitted dependency/test changes. Report the new behavior, passing tests, remaining warnings, and limits: IP limits are not Sybil resistance; tokens are still bearer credentials; PQ key exchange is a separate stage. Leave all changes uncommitted unless the user explicitly requests a commit.
