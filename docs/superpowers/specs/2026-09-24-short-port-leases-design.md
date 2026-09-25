# Short Port Leases for GameNet

## Purpose

Anyone can start a TCP game tunnel with one command and share its relay address. A brief network interruption or relay restart should let that host recover the same public port. A token must not reserve a port indefinitely. Permanent addresses, accounts, and a new player-facing protocol are outside this change.

## Behavior

- A lease belongs to the agent's existing 32-byte token. One token has at most one active tunnel. A second live connection presenting that token is rejected; it does not displace the first.
- A new token receives an available port in `10000..=10999`. The relay binds the TCP listener and durably records the lease before sending `TunnelReady`.
- On an agent disconnect, the listener and its player forwarding tasks stop. The lease enters grace for 300 seconds, counted from the disconnect. The port cannot be given to anyone else during grace. A reconnect with the same token may resume it, even from a new IP address, subject to the IP quota.
- After grace expires, the port can be allocated to another host. If the former host reconnects after expiry, it receives any available port; it might happen to receive the old one, but that is no longer guaranteed.
- While the CLI stays running, it retries after a lost relay connection with delays of 1, 2, 4, 8, then at most 15 seconds. It uses the same identity token and prints the public address on each successful registration, including when the port changes. Stopping the CLI stops retries.
- Cleanup checks the active session ID. A late cleanup call from a previous connection cannot release a newer connection's lease.
- Active leases are refreshed in durable storage every 30 seconds with an expiry 300 seconds after the refresh. On relay startup, every unexpired saved lease loads as a grace lease. A crash therefore leaves roughly 270–300 seconds of recovery time, depending on the last refresh. A clean disconnect starts a fresh 300-second grace window.
- Registration is sent only after the QUIC handshake completes. There is no 0-RTT path for state-changing registration in this version.
- A pending handshake and first registration message have a 10-second application deadline. At most 128 connections may be in this pre-registration stage at once; the permit is released when registration succeeds or fails.
- A TCP player counts as active until both forwarding directions have finished or one fails. An end-of-stream in one direction must close that write direction and allow the other direction to drain; shutdown must not leave detached copy tasks. The relay also has a global player limit of 2,000 in addition to the existing 50-per-tunnel limit.
- Reject `Protocol::Udp` explicitly. Until UDP forwarding exists, UDP-only game presets must fail with a clear message instead of silently making a TCP tunnel; documentation must say TCP-only.

## State and storage

Keep one in-memory lease table under the existing server-state mutex. Its states are `Active(session_id, peer_ip)` and `Grace(expires_at, last_ip)`. A candidate port is selected and bound while that mutex is held, then the activation is saved before `TunnelReady` is sent. This avoids a second in-memory registry or a persistent `Pending` state. The lock must not be held while awaiting registration messages or forwarding traffic.

The versioned JSON file contains only token fingerprints, ports, optional last IP addresses, and Unix expiry times. A fingerprint is SHA-256 of a cryptographically random 32-byte token; the relay never needs to store the bearer token itself. The IP is optional only for migrated legacy records, which did not record one. At startup, validate the schema, port range, duplicate token fingerprints and ports, and file size. Malformed state must fail startup instead of silently starting empty. Writes use a same-directory temporary file, `sync_all`, and atomic rename. If saving an allocation fails, registration fails and the bound listener closes. If saving a disconnection or periodic refresh fails, the relay logs a high-severity error and stops accepting new registrations until persistence works; it must not pretend the lease is safely recorded.

Keep the existing limit of five **active plus grace leases** per last IP, and enforce the 1,000-port capacity. A reconnect from a new IP transfers the lease's quota charge only if the destination IP has room. Expire leases before checking capacity. These limits are admission controls, not a complete defense against people changing IP addresses or holding many live connections.

## Migration

The current `gamenet-state.json` contains permanent token-to-port assignments without activity timestamps or IP addresses. At the first startup of the new relay, make an owner-only backup, validate every old entry, hash each token, and convert all assignments to grace leases ending 300 seconds after migration. Their IP field stays empty until the host reconnects. Recently active hosts can reclaim their old ports. Other old reservations expire after five minutes. A full legacy pool can therefore delay new allocations during this one-time window. Write the new version atomically and never silently reset a malformed file. If startup stops after creating the backup, reuse an identical backup or safely complete a partial backup on the next attempt; reject a backup whose content differs from the legacy source. Treat the backup as a secret because it contains bearer tokens, and document its removal after successful deployment.

## Verification and limits

Unit tests use explicit times for lease transitions and restarts. Integration tests use real local QUIC and TCP sockets to check registration, duplicate tokens, disconnect cleanup, listener binding failure, restart recovery, expiry, half-close forwarding, and no cross-session cleanup. Test malformed and duplicate persisted records, simulated write failures, player-limit release, and explicit UDP rejection. Preserve the existing TLS certificate tests.

This change covers TCP game tunnels. Separate work is still needed for broader public-relay abuse controls, credential-file permissions and revocation, UDP forwarding, and post-quantum key exchange.
