use crate::bridge;
use crate::state::ServerState;
use gamenet_core::message::{recv_msg, send_msg};
use gamenet_core::protocol::ControlMessage;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{info, warn};

/// Represents one active tunnel between an agent and its players.
pub struct Tunnel {
    control_stream: TcpStream,
    state: Arc<Mutex<ServerState>>,
    public_port: u16,
    local_port: u16,
    stream_counter: u64,
}

impl Tunnel {
    /// Wait for a registration message, assign a public port, and confirm.
    pub async fn from_connection(
        mut stream: TcpStream,
        state: Arc<Mutex<ServerState>>,
    ) -> anyhow::Result<Self> {
        // Wait for the Register message
        let msg = recv_msg(&mut stream)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Agent disconnected before registering"))?;

        let local_port = match msg {
            ControlMessage::Register { local_port, .. } => local_port,
            other => {
                warn!("Expected Register, got {:?}", other);
                anyhow::bail!("Invalid first message");
            }
        };

        // Assign a public port from the registry
        let public_port = {
            let mut s = state.lock().await;
            s.assign_port(local_port)
        };

        // Confirm to the agent
        send_msg(&mut stream, &ControlMessage::TunnelReady { public_port }).await?;

        Ok(Self {
            control_stream: stream,
            state,
            public_port,
            local_port,
            stream_counter: 0,
        })
    }

    /// Accept players in a loop and bridge them to the agent.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        let player_listener =
            TcpListener::bind(format!("0.0.0.0:{}", self.public_port)).await?;
        info!(
            "Tunnel LIVE: port {} -> Agent local port {}",
            self.public_port, self.local_port
        );

        loop {
            let (player_stream, player_addr) = player_listener.accept().await?;
            info!("Player {} connected.", player_addr);

            // Bind a random data port for this player
            let data_listener = TcpListener::bind("0.0.0.0:0").await?;
            let data_port = data_listener.local_addr()?.port();

            // Signal the agent
            self.stream_counter += 1;
            send_msg(
                &mut self.control_stream,
                &ControlMessage::NewConnection {
                    stream_id: self.stream_counter,
                    data_port,
                },
            )
            .await?;

            // Wait for agent data connection
            let (agent_data_stream, _) = data_listener.accept().await?;
            info!(
                "Agent data connection established for player {}",
                player_addr
            );

            // Bridge in background
            bridge::spawn_bridge(player_stream, agent_data_stream, player_addr);
        }
    }

    /// Remove this tunnel from the registry.
    pub async fn cleanup(&self) {
        let mut s = self.state.lock().await;
        s.remove(self.public_port);
        info!("Tunnel on port {} cleaned up.", self.public_port);
    }
}
