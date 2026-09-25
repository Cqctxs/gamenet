# Required Hybrid Post-Quantum Key Exchange for GameNet

## Purpose and scope

GameNet is not publicly deployed, so there are no existing agent versions to preserve. Every successful agent-to-relay QUIC connection should use rustls's `X25519MLKEM768` hybrid key exchange. A peer that offers only conventional key exchange must fail the TLS handshake. There is no compatibility fallback, configuration switch, or custom cryptographic implementation.

This change covers the key exchange that establishes the encrypted QUIC connection. The server certificate remains conventionally authenticated, and the player-to-relay TCP connection remains outside GameNet's encryption. Documentation and any user-facing claim must keep those limits explicit.

## TLS configuration

Use the maintained `aws-lc-rs` provider supplied by rustls 0.23 on both agent and relay. Configure its supported key-exchange groups explicitly to **only** `X25519MLKEM768`, rather than relying on provider defaults or ordering. Build rustls TLS 1.3 client and server configurations with that provider, then wrap them with Quinn's `QuicClientConfig` and `QuicServerConfig`. Apply the same group restriction to verified clients, the development-only insecure client, file-backed production server certificates, and development self-signed server certificates. Certificate validation and hostname checking remain enabled for normal clients. Registration continues only after the QUIC handshake; do not reintroduce 0-RTT.

Pin the necessary rustls and Quinn features for `aws-lc-rs` explicitly. Keep dependencies needed elsewhere in the repository; removing a direct `ring` dependency used outside TLS is not part of this change. Verify the provider builds on the intended development and Linux deployment targets before rollout.

## Production certificate behavior

The public relay must have both `GAMENET_TLS_CERT` and `GAMENET_TLS_KEY` set to readable, valid files. Missing either file or a failed parse must stop startup with a clear error. Self-signed server certificates remain available only through an explicit development mode, so a missing production setting cannot silently select one. Tests should inject the development configuration directly rather than changing process-wide environment variables in parallel tests.

Certificate issuance, secure key-file access, renewal, and service setup remain deployment tasks. The relay currently loads its certificate at startup, so renewal needs a restart until certificate reload is implemented separately. A restart interrupts active tunnels; the CLI retry and five-minute port lease mitigate that interruption.

## Failure behavior and verification

Write failing tests before the implementation. Unit tests should assert that the configured provider exposes only `X25519MLKEM768` and that production startup rejects missing or incomplete certificate settings. Local QUIC integration tests should establish a verified connection between the new agent and relay, then show that a conventional-only client cannot connect to the new relay and that the new agent cannot connect to a conventional-only server. Keep tests for untrusted, expired, and wrong-host certificates. A successful connection with only one configured group proves that the negotiated key exchange was hybrid without relying on Quinn's test-only negotiated-group field.

Measure handshake bytes, connection time, and CPU use against the current conventional build, including a packet-loss scenario. Measure steady-state tunnel throughput and latency separately. Treat these as benchmark results tied to hardware and network conditions, not as guarantees for all players. A production claim can say that GameNet requires hybrid post-quantum key exchange for its agent-to-relay QUIC tunnel; it cannot claim quantum-resistant certificate authentication or end-to-end protection for players.

## Source basis

- [rustls 0.23.45 `aws-lc-rs` key-exchange groups](https://docs.rs/rustls/0.23.45/rustls/crypto/aws_lc_rs/kx_group/index.html)
- [rustls provider configuration](https://docs.rs/rustls/0.23.45/rustls/crypto/struct.CryptoProvider.html)
- [Quinn's post-quantum QUIC integration test](https://docs.rs/crate/quinn/0.11.12/source/tests/post_quantum.rs)
