use crate::state::ServerState;
use crate::tunnel::Tunnel;
use quinn::Endpoint;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info};

/// The main relay server.
///
/// Listens for agent QUIC connections and spawns a [Tunnel] for each one.
pub struct RelayServer {
    state: Arc<Mutex<ServerState>>,
    endpoint: Endpoint,
}

impl RelayServer {
    /// Bind the QUIC relay server to the given address (e.g. `"0.0.0.0:5000"`).
    pub async fn bind(addr: &str) -> anyhow::Result<Self> {
        let (server_config, _cert) = gamenet_core::crypto::server_config()?;
        let endpoint = Endpoint::server(server_config, addr.parse()?)?;
        info!("QUIC relay server listening on {}", addr);
        Ok(Self {
            state: Arc::new(Mutex::new(ServerState::new())),
            endpoint,
        })
    }

    /// Run the server loop, accepting agent QUIC connections forever.
    pub async fn run(&self) -> anyhow::Result<()> {
        while let Some(incoming) = self.endpoint.accept().await {
            let state = Arc::clone(&self.state);
            tokio::spawn(async move {
                let addr = incoming.remote_address();
                match incoming.await {
                    Ok(connection) => {
                        info!("Agent connected from {} (QUIC)", addr);
                        match Tunnel::from_quic(connection, state).await {
                            Ok(mut tunnel) => {
                                if let Err(e) = tunnel.run().await {
                                    error!("Agent {} tunnel error: {}", addr, e);
                                }
                                tunnel.cleanup().await;
                            }
                            Err(e) => {
                                error!("Agent {} failed to register: {}", addr, e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("QUIC handshake failed from {}: {}", addr, e);
                    }
                }
            });
        }
        Ok(())
    }
}
