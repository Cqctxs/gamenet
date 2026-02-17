use crate::bridge;
use gamenet_core::message::{recv_msg, send_msg};
use gamenet_core::protocol::{ControlMessage, Protocol};
use tokio::net::TcpStream;
use tracing::{error, info};

/// The agent-side tunnel that connects to the relay server.
pub struct AgentTunnel {
    control_stream: TcpStream,
    server_ip: String,
    local_port: u16,
}

impl AgentTunnel {
    /// Connect to the relay server and register a tunnel.
    pub async fn connect(server_ip: &str, local_port: u16) -> anyhow::Result<Self> {
        let control_addr = format!("{}:5001", server_ip);
        let mut control_stream = TcpStream::connect(&control_addr).await?;
        info!("Connected to relay server at {}", control_addr);

        // Send registration
        send_msg(
            &mut control_stream,
            &ControlMessage::Register {
                protocol: Protocol::Tcp,
                local_port,
            },
        )
        .await?;

        // Wait for confirmation
        let msg = recv_msg(&mut control_stream)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Server closed before confirming tunnel"))?;

        match msg {
            ControlMessage::TunnelReady { public_port } => {
                info!("===========================================");
                info!("  TUNNEL IS LIVE!");
                info!("  Tell players to connect to:");
                info!("    {}:{}", server_ip, public_port);
                info!("===========================================");
            }
            ControlMessage::Error { message } => {
                anyhow::bail!("Server rejected registration: {}", message);
            }
            other => {
                anyhow::bail!("Unexpected response: {:?}", other);
            }
        }

        Ok(Self {
            control_stream,
            server_ip: server_ip.to_string(),
            local_port,
        })
    }

    /// Run the tunnel, listening for new player signals forever.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            let msg = match recv_msg(&mut self.control_stream).await? {
                Some(m) => m,
                None => {
                    info!("Server disconnected. Shutting down.");
                    break;
                }
            };

            if let ControlMessage::NewConnection {
                stream_id,
                data_port,
            } = msg
            {
                info!(
                    "Player #{} joined! Opening data tunnel on port {}...",
                    stream_id, data_port
                );

                let data_addr = format!("{}:{}", self.server_ip, data_port);
                let local_game_addr = format!("127.0.0.1:{}", self.local_port);

                tokio::spawn(async move {
                    if let Err(e) = bridge::bridge_player(&data_addr, &local_game_addr).await {
                        error!("Player #{} bridge error: {}", stream_id, e);
                    }
                    info!("Player #{} disconnected.", stream_id);
                });
            }
        }

        Ok(())
    }
}
