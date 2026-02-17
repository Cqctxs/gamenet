use crate::bridge;
use crate::state::ServerState;
use gamenet_core::message::{recv_msg, send_msg};
use gamenet_core::protocol::ControlMessage;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{info, warn};

/// One active tunnel between an agent and its players.
pub struct Tunnel {
    control_stream: TcpStream,
    state: Arc<Mutex<ServerState>>,
    public_port: u16,
    local_port: u16,
    stream_counter: u64,
}

impl Tunnel {
    /// Perform the handshake: read Register, assign a port, send TunnelReady.
    pub async fn from_connection(
        mut stream: TcpStream,
        state: Arc<Mutex<ServerState>>,
    ) -> anyhow::Result<Self> {
        let msg = recv_msg(&mut stream)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Agent disconnected before registering"))?;

        let ControlMessage::Register { local_port, .. } = msg else {
            warn!("Expected Register, got {:?}", msg);
            anyhow::bail!("Invalid first message");
        };

        let public_port = state.lock().await.assign_port(local_port);
        send_msg(&mut stream, &ControlMessage::TunnelReady { public_port }).await?;

        Ok(Self { control_stream: stream, state, public_port, local_port, stream_counter: 0 })
    }

    /// Accept players in a loop and bridge each one to the agent.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.public_port)).await?;
        info!("Tunnel LIVE  :{} -> agent :{}", self.public_port, self.local_port);

        loop {
            let (player, addr) = listener.accept().await?;
            info!("Player {addr} connected");

            // Open a one-time data port and tell the agent to connect back
            let data_listener = TcpListener::bind("0.0.0.0:0").await?;
            self.stream_counter += 1;
            send_msg(&mut self.control_stream, &ControlMessage::NewConnection {
                stream_id: self.stream_counter,
                data_port: data_listener.local_addr()?.port(),
            }).await?;

            let (agent_data, _) = data_listener.accept().await?;
            bridge::spawn_bridge(player, agent_data, addr);
        }
    }

    /// Remove this tunnel from the registry.
    pub async fn cleanup(&self) {
        self.state.lock().await.remove(self.public_port);
        info!("Tunnel on port {} cleaned up", self.public_port);
    }
}
