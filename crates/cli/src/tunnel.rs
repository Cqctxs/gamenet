use crate::bridge;
use gamenet_core::crypto;
use gamenet_core::message::{recv_msg, send_msg};
use gamenet_core::protocol::{ControlMessage, Protocol};
use quinn::{Connection, Endpoint};
use tracing::{error, info};

/// The agent-side tunnel that connects to the relay server via QUIC.
pub struct AgentTunnel {
    quic: Connection,
    local_port: u16,
}

impl AgentTunnel {
    /// Connect to the relay server over QUIC and register a tunnel.
    pub async fn connect(server_ip: &str, local_port: u16) -> anyhow::Result<Self> {
        // Build an insecure client config (dev: self-signed certs)
        let client_config = crypto::insecure_client_config()?;
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_config);

        // QUIC connect to the relay server on port 5000
        let server_addr = format!("{}:5000", server_ip);
        let quic = endpoint.connect(server_addr.parse()?, "localhost")?.await?;
        info!("QUIC connection established to {}", server_addr);

        // Open the first bi-stream as the control channel
        let (mut ctrl_send, mut ctrl_recv) = quic.open_bi().await?;

        // Send registration
        send_msg(
            &mut ctrl_send,
            &ControlMessage::Register {
                protocol: Protocol::Tcp,
                local_port,
            },
        )
        .await?;

        // Wait for confirmation
        let msg = recv_msg(&mut ctrl_recv)
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

        // Spawn a task to listen for control messages (NewConnection notifications)
        tokio::spawn(async move {
            if let Err(e) = Self::handle_control_messages(ctrl_recv).await {
                error!("Control channel error: {}", e);
            }
        });

        Ok(Self { quic, local_port })
    }

    /// Listen for control messages from the server (informational only).
    async fn handle_control_messages(mut ctrl_recv: quinn::RecvStream) -> anyhow::Result<()> {
        loop {
            let msg = match recv_msg(&mut ctrl_recv).await? {
                Some(m) => m,
                None => {
                    info!("Control channel closed by server.");
                    break;
                }
            };

            if let ControlMessage::NewConnection { stream_id } = msg {
                info!("Player #{} joined! Accepting QUIC stream...", stream_id);
            }
        }
        Ok(())
    }

    /// Accept new QUIC bi-streams opened by the server (one per player)
    /// and bridge each one to the local game.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            // The server opens a new bi-stream for each player
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
