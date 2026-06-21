# Let's Encrypt TLS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the current MITM-vulnerable `insecure_client_config()` with proper Let's Encrypt certificate verification so end users can safely download and run `gamenet host minecraft` against `relay.0verclock.tech` without any certificate warnings or manual trust steps.

**Architecture:** The server reads its TLS certificate and private key from paths supplied via `GAMENET_TLS_CERT` / `GAMENET_TLS_KEY` environment variables (standard certbot output at `/etc/letsencrypt/live/relay.0verclock.tech/`); if those vars are absent it falls back to a self-signed cert for local development. The CLI client validates the server cert against Mozilla's bundled CA roots (`webpki-roots`), using the server hostname as the SNI name so the Let's Encrypt cert for `relay.0verclock.tech` is accepted automatically. A hidden `--insecure` flag preserves the dev workflow of connecting to a local server without a real cert.

**Tech Stack:** `rustls-pemfile = "2"` (parse PEM files), `webpki-roots = "0.26"` (CA root bundle), existing `rustls 0.23` + `quinn 0.11`

---

## Deployment prerequisites (run once on the VPS)

Before any of this code matters, the server machine needs a real cert. Point `relay.0verclock.tech` at your VPS IP in your DNS panel, then:

```bash
# Install certbot (Debian/Ubuntu)
sudo apt install certbot

# Obtain cert — temporarily binds port 80, no web server needed
sudo certbot certonly --standalone -d relay.0verclock.tech

# Certs land at:
#   /etc/letsencrypt/live/relay.0verclock.tech/fullchain.pem  (cert chain)
#   /etc/letsencrypt/live/relay.0verclock.tech/privkey.pem    (private key)

# Auto-renewal is set up by certbot automatically via a systemd timer.
# After renewal, restart the server:
#   sudo systemctl restart gamenet  (or however you run it)
```

---

## File map

| Action | Path | Responsibility |
|--------|------|----------------|
| Modify | `crates/core/Cargo.toml` | Add `rustls-pemfile` and `webpki-roots` |
| Modify | `crates/core/src/crypto.rs` | Add `server_config_from_files()` and `client_config()` |
| Modify | `crates/server/src/relay.rs` | Load cert from env vars, fall back to self-signed |
| Modify | `crates/cli/src/tunnel.rs` | Use verified TLS, pass hostname as SNI, accept `insecure` flag |
| Modify | `crates/cli/src/main.rs` | Add `--insecure` flag, default `--server` to `relay.0verclock.tech` |

---

### Task 1: Add `rustls-pemfile` and `webpki-roots` to core

**Files:**
- Modify: `crates/core/Cargo.toml`

- [ ] **Step 1: Add the deps**

In `crates/core/Cargo.toml`, append to `[dependencies]`:

```toml
rustls-pemfile = "2"
webpki-roots = "0.26"
```

- [ ] **Step 2: Verify compilation**

```bash
cargo build -p gamenet-core
```

Expected: success (new crates downloaded and compiled, no errors).

- [ ] **Step 3: Commit**

```bash
git add crates/core/Cargo.toml Cargo.lock
git commit -m "chore: add rustls-pemfile and webpki-roots deps"
```

---

### Task 2: Add `server_config_from_files()` and `client_config()` to `crypto.rs`

**Files:**
- Modify: `crates/core/src/crypto.rs`

- [ ] **Step 1: Write the failing tests**

Append to `crates/core/src/crypto.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_config_builds_successfully() {
        assert!(client_config().is_ok());
    }

    #[test]
    fn server_config_from_files_loads_valid_pem_cert() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let dir = std::env::temp_dir();
        let cert_path = dir.join(format!("gamenet-test-cert-{}.pem", ns));
        let key_path = dir.join(format!("gamenet-test-key-{}.pem", ns));

        // Generate a self-signed cert using the same rcgen already in use
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen should generate cert");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

        let result = server_config_from_files(&cert_path, &key_path);
        assert!(result.is_ok(), "should load valid cert: {:?}", result.err());

        std::fs::remove_file(&cert_path).ok();
        std::fs::remove_file(&key_path).ok();
    }

    #[test]
    fn server_config_from_files_fails_on_missing_file() {
        let result = server_config_from_files(
            std::path::Path::new("/nonexistent/cert.pem"),
            std::path::Path::new("/nonexistent/key.pem"),
        );
        assert!(result.is_err());
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p gamenet-core crypto
```

Expected: FAIL — `client_config` and `server_config_from_files` are not defined yet.

- [ ] **Step 3: Implement both functions**

Replace the full `crates/core/src/crypto.rs`:

```rust
use std::path::Path;
use std::sync::Arc;

use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, ServerConfig};
use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;
use rustls::client::danger;
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};

// ── Server-side: self-signed cert (development only) ─────────────────────────

pub fn server_config() -> anyhow::Result<(ServerConfig, CertificateDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    let mut server_config = ServerConfig::with_single_cert(vec![cert_der.clone()], key_der.into())?;
    let transport = Arc::get_mut(&mut server_config.transport).unwrap();
    transport.max_concurrent_bidi_streams(128u8.into());

    Ok((server_config, cert_der))
}

/// Load a TLS certificate chain and private key from PEM files and build a
/// quinn [`ServerConfig`].  Compatible with Let's Encrypt / certbot output
/// (`fullchain.pem` + `privkey.pem`).
pub fn server_config_from_files(cert_path: &Path, key_path: &Path) -> anyhow::Result<ServerConfig> {
    let cert_pem = std::fs::read(cert_path)
        .map_err(|e| anyhow::anyhow!("Cannot read cert {:?}: {}", cert_path, e))?;
    let key_pem = std::fs::read(key_path)
        .map_err(|e| anyhow::anyhow!("Cannot read key {:?}: {}", key_path, e))?;

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("Failed to parse cert PEM: {}", e))?;

    anyhow::ensure!(!certs.is_empty(), "No certificates found in {:?}", cert_path);

    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .map_err(|e| anyhow::anyhow!("Failed to parse key PEM: {}", e))?
        .ok_or_else(|| anyhow::anyhow!("No private key found in {:?}", key_path))?;

    let mut server_config = ServerConfig::with_single_cert(certs, key)?;
    let transport = Arc::get_mut(&mut server_config.transport).unwrap();
    transport.max_concurrent_bidi_streams(128u8.into());

    Ok(server_config)
}

// ── Client-side: verified TLS against Mozilla CA roots ───────────────────────

/// Build a quinn [`ClientConfig`] that validates the server certificate against
/// Mozilla's bundled CA roots.  Works transparently with Let's Encrypt certs.
pub fn client_config() -> anyhow::Result<ClientConfig> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.enable_early_data = true; // preserve QUIC 0-RTT on reconnections
    let quic_crypto = QuicClientConfig::try_from(crypto)?;
    Ok(ClientConfig::new(Arc::new(quic_crypto)))
}

/// Build a quinn [`ClientConfig`] that skips all certificate verification.
///
/// ⚠️  Development only — use only with `--insecure` flag against a local server.
pub fn insecure_client_config() -> anyhow::Result<ClientConfig> {
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    crypto.enable_early_data = true;
    let quic_crypto = QuicClientConfig::try_from(crypto)?;
    Ok(ClientConfig::new(Arc::new(quic_crypto)))
}

// ── SkipServerVerification (dev helper) ──────────────────────────────────────

#[derive(Debug)]
struct SkipServerVerification(Arc<CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<danger::ServerCertVerified, rustls::Error> {
        Ok(danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_config_builds_successfully() {
        assert!(client_config().is_ok());
    }

    #[test]
    fn server_config_from_files_loads_valid_pem_cert() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let dir = std::env::temp_dir();
        let cert_path = dir.join(format!("gamenet-test-cert-{}.pem", ns));
        let key_path = dir.join(format!("gamenet-test-key-{}.pem", ns));

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen should generate cert");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

        let result = server_config_from_files(&cert_path, &key_path);
        assert!(result.is_ok(), "should load valid cert: {:?}", result.err());

        std::fs::remove_file(&cert_path).ok();
        std::fs::remove_file(&key_path).ok();
    }

    #[test]
    fn server_config_from_files_fails_on_missing_file() {
        let result = server_config_from_files(
            Path::new("/nonexistent/cert.pem"),
            Path::new("/nonexistent/key.pem"),
        );
        assert!(result.is_err());
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p gamenet-core crypto
```

Expected: 3 PASS

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/crypto.rs
git commit -m "feat: add server_config_from_files and verified client_config"
```

---

### Task 3: Update the server to load cert from environment variables

**Files:**
- Modify: `crates/server/src/relay.rs`

The server checks `GAMENET_TLS_CERT` and `GAMENET_TLS_KEY`. If both are set, it loads the real cert (production). Otherwise it falls back to a fresh self-signed cert with a clear warning (development).

- [ ] **Step 1: Replace the full `crates/server/src/relay.rs`**

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
        let server_config = match (
            std::env::var("GAMENET_TLS_CERT"),
            std::env::var("GAMENET_TLS_KEY"),
        ) {
            (Ok(cert_path), Ok(key_path)) => {
                info!("Loading TLS cert from {}", cert_path);
                gamenet_core::crypto::server_config_from_files(
                    std::path::Path::new(&cert_path),
                    std::path::Path::new(&key_path),
                )?
            }
            _ => {
                warn!(
                    "GAMENET_TLS_CERT / GAMENET_TLS_KEY not set — \
                     using self-signed cert (development mode only)"
                );
                let (cfg, _cert) = gamenet_core::crypto::server_config()?;
                cfg
            }
        };

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

- [ ] **Step 2: Build the server crate**

```bash
cargo build -p server
```

Expected: success.

- [ ] **Step 3: Smoke-test both paths**

**Dev mode (no env vars — should warn and start):**
```bash
cargo run -p server
```
Expected log output:
```
WARN ... GAMENET_TLS_CERT / GAMENET_TLS_KEY not set — using self-signed cert (development mode only)
INFO ... QUIC relay server listening on 0.0.0.0:5000
```
Stop with Ctrl-C.

**Production mode (with real cert files — on the VPS, or with a temp self-signed PEM for testing):**

To verify the env var path loads without error, generate temp PEM files using the rcgen test helper and run:
```bash
# quick one-liner to make test PEM files
cargo test -p gamenet-core server_config_from_files_loads -- --nocapture
# then set env vars pointing at the temp files the test created and restart
GAMENET_TLS_CERT=/tmp/gamenet-test-cert-*.pem \
GAMENET_TLS_KEY=/tmp/gamenet-test-key-*.pem \
cargo run -p server
```
Expected log:
```
INFO ... Loading TLS cert from /tmp/gamenet-test-cert-...pem
INFO ... QUIC relay server listening on 0.0.0.0:5000
```
Stop with Ctrl-C.

- [ ] **Step 4: Commit**

```bash
git add crates/server/src/relay.rs
git commit -m "feat: load Let's Encrypt cert from GAMENET_TLS_CERT/GAMENET_TLS_KEY env vars"
```

---

### Task 4: Update the CLI — verified TLS, correct SNI, `--insecure` flag, production default

**Files:**
- Modify: `crates/cli/src/tunnel.rs`
- Modify: `crates/cli/src/main.rs`

Two problems to fix simultaneously:
1. The SNI is hardcoded to `"localhost"` — must use the actual server hostname so the Let's Encrypt cert for `relay.0verclock.tech` validates.
2. `AgentTunnel::connect` uses `insecure_client_config()` — swap to `client_config()` by default.
3. Add an `insecure: bool` parameter for local dev (self-signed server).

- [ ] **Step 1: Write the failing test**

Append to `crates/cli/src/tunnel.rs`:

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

    // Verify that client_config() is wired in by default (no panic / no error)
    #[test]
    fn verified_client_config_builds() {
        assert!(gamenet_core::crypto::client_config().is_ok());
    }
}
```

- [ ] **Step 2: Run tests to verify they pass already (both are pure unit tests)**

```bash
cargo test -p cli
```

Expected: PASS — identity test already works; client_config test exercises Task 2's code.

- [ ] **Step 3: Replace the full `crates/cli/src/tunnel.rs`**

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
    /// Connect to the relay server.
    ///
    /// `server_hostname` is used both for DNS resolution and as the TLS SNI
    /// name, so it must match the server's certificate (e.g. `relay.0verclock.tech`).
    /// Set `insecure = true` only for local development against a self-signed cert.
    pub async fn connect(
        server_hostname: &str,
        local_port: u16,
        insecure: bool,
    ) -> anyhow::Result<Self> {
        let token = identity::load_or_create()?;

        let client_config = if insecure {
            crypto::insecure_client_config()?
        } else {
            crypto::client_config()?
        };

        let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_config);

        let server_addr = format!("{}:5000", server_hostname);
        let resolved: std::net::SocketAddr = match server_addr.parse() {
            Ok(addr) => addr,
            Err(_) => tokio::net::lookup_host(&server_addr)
                .await?
                .next()
                .ok_or_else(|| anyhow::anyhow!("Could not resolve {}", server_addr))?,
        };
        info!("Connecting to {} ({})", server_hostname, resolved);

        // SNI must be the hostname, not the IP, for cert validation to work
        let connecting = endpoint.connect(resolved, server_hostname)?;

        let quic = match connecting.into_0rtt() {
            Ok((conn, zero_rtt_accepted)) => {
                info!("0-RTT connection attempt to {}", server_hostname);
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
                info!("Full QUIC handshake to {}", server_hostname);
                connecting.await?
            }
        };
        info!("QUIC connection established to {}", server_hostname);

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
                info!("    {}:{}", server_hostname, public_port);
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

    #[test]
    fn verified_client_config_builds() {
        assert!(gamenet_core::crypto::client_config().is_ok());
    }
}
```

- [ ] **Step 4: Update `crates/cli/src/main.rs`**

Replace the full file:

```rust
mod bridge;
mod tunnel;

use clap::{Parser, Subcommand};
use gamenet_core::presets;
use tunnel::AgentTunnel;

#[derive(Parser)]
#[command(
    name = "gamenet",
    about = "GameNet — tunnel your local game server to the internet"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Host a game server through the relay
    ///
    /// Supported games: minecraft, bedrock, valheim, terraria, factorio
    Host {
        /// Game name (e.g. "minecraft") or omit and use --port
        game: Option<String>,

        /// Local port to tunnel (overrides game preset)
        #[arg(short, long)]
        port: Option<u16>,

        /// Relay server hostname
        #[arg(long, default_value = "relay.0verclock.tech", hide = true)]
        server: String,

        /// Skip TLS certificate verification (development only — do not use in production)
        #[arg(long, default_value_t = false, hide = true)]
        insecure: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Host { game, port, server, insecure } => {
            let local_port = match (&game, port) {
                (_, Some(p)) => p,
                (Some(name), None) => {
                    let preset = presets::find_preset(name).ok_or_else(|| {
                        let available: Vec<&str> =
                            presets::PRESETS.iter().map(|p| p.name).collect();
                        anyhow::anyhow!(
                            "Unknown game '{}'. Available: {}\n\
                             Or specify a port directly with: gamenet host --port <PORT>",
                            name,
                            available.join(", ")
                        )
                    })?;
                    println!(
                        "{} — using default port {}",
                        preset.name, preset.default_port
                    );
                    preset.default_port
                }
                (None, None) => {
                    let available: Vec<&str> = presets::PRESETS.iter().map(|p| p.name).collect();
                    anyhow::bail!(
                        "Please specify a game or port.\n\n\
                         Usage:\n  \
                         gamenet host minecraft\n  \
                         gamenet host --port 7777\n\n\
                         Supported games: {}",
                        available.join(", ")
                    );
                }
            };

            let mut tunnel = AgentTunnel::connect(&server, local_port, insecure).await?;
            tunnel.run().await
        }
    }
}
```

- [ ] **Step 5: Build and run all tests**

```bash
cargo build && cargo test
```

Expected: all 12 tests PASS, zero compile errors.

- [ ] **Step 6: Smoke-test dev workflow (requires the server running locally)**

In one terminal:
```bash
cargo run -p server
# Should warn: using self-signed cert (development mode only)
```

In a second terminal:
```bash
cargo run -p cli -- host --port 25565 --server localhost --insecure
```
Expected: tunnel registers and logs `TUNNEL IS LIVE!`.

Without `--insecure`:
```bash
cargo run -p cli -- host --port 25565 --server localhost
```
Expected: connection attempt fails with a TLS certificate error (self-signed cert is not in CA roots). This confirms verification is active.

- [ ] **Step 7: Commit**

```bash
git add crates/cli/src/tunnel.rs crates/cli/src/main.rs
git commit -m "feat: verified TLS against CA roots, correct SNI, --insecure dev flag, default server relay.0verclock.tech"
```

---

## Self-review against the spec

| Requirement | Task |
|---|---|
| Verified TLS against Let's Encrypt cert | Task 2 (`client_config()`) + Task 4 (CLI wired) |
| Server loads real cert from disk | Task 3 (`GAMENET_TLS_CERT` / `GAMENET_TLS_KEY`) |
| Dev fallback to self-signed cert | Task 3 (no env vars → warns + uses `server_config()`) |
| Dev CLI bypass (`--insecure`) | Task 4 |
| Correct SNI hostname (not `"localhost"`) | Task 4 (`server_hostname` passed to `endpoint.connect`) |
| Default server `relay.0verclock.tech` | Task 4 (`main.rs` default) |
| QUIC 0-RTT preserved | Tasks 2 & 4 (`enable_early_data = true` in both configs) |
| TCP player leg | Intentionally out of scope — transparent proxy, same tradeoff as ngrok |
