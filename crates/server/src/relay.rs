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
