use crate::state::ServerState;
use crate::tunnel::Tunnel;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{error, info};

/// The main relay server.
///
/// Listens for agent connections on the control port and spawns
/// a [Tunnel] for each one.
pub struct RelayServer {
    state: Arc<Mutex<ServerState>>,
    control_listener: TcpListener,
}

impl RelayServer {
    /// Bind the relay server to the given address (e.g. `"0.0.0.0:5001"`).
    pub async fn bind(addr: &str) -> anyhow::Result<Self> {
        let control_listener = TcpListener::bind(addr).await?;
        info!("Server: Control port open on {}", addr);
        Ok(Self {
            state: Arc::new(Mutex::new(ServerState::new())),
            control_listener,
        })
    }

    /// Run the server loop, accepting agent connections forever.
    pub async fn run(&self) -> anyhow::Result<()> {
        loop {
            let (stream, addr) = self.control_listener.accept().await?;
            info!("Agent connected from: {}", addr);

            let state = Arc::clone(&self.state);
            tokio::spawn(async move {
                match Tunnel::from_connection(stream, state).await {
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
            });
        }
    }
}
