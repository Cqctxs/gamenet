use crate::bridge;
use crate::state::ServerState;
use gamenet_core::message::{recv_msg, send_msg};
use gamenet_core::protocol::ControlMessage;
use quinn::{Connection, SendStream};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

/// One active tunnel between an agent and its players.
///
/// The agent holds a single QUIC connection to the server.
/// The first bi-stream is the **control channel**.
/// Each new player gets a fresh QUIC bi-stream (multiplexing).
pub struct Tunnel {
    quic: Connection,
    ctrl_send: SendStream,
    state: Arc<Mutex<ServerState>>,
    public_port: u16,
    local_port: u16,
    stream_counter: u64,
}

impl Tunnel {
    /// Perform the handshake over the first QUIC bi-stream (control channel).
    pub async fn from_quic(
        conn: Connection,
        state: Arc<Mutex<ServerState>>,
    ) -> anyhow::Result<Self> {
        // The agent opens the first bi-stream as the control channel
        let (mut ctrl_send, mut ctrl_recv) = conn.accept_bi().await?;

        let msg = recv_msg(&mut ctrl_recv)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Agent disconnected before registering"))?;

        let ControlMessage::Register { local_port, .. } = msg else {
            warn!("Expected Register, got {:?}", msg);
            anyhow::bail!("Invalid first message");
        };

        let public_port = state.lock().await.assign_port(local_port);
        send_msg(&mut ctrl_send, &ControlMessage::TunnelReady { public_port }).await?;

        info!(
            "Tunnel registered: public :{} -> agent :{}",
            public_port, local_port
        );

        Ok(Self {
            quic: conn,
            ctrl_send,
            state,
            public_port,
            local_port,
            stream_counter: 0,
        })
    }

    /// Accept TCP players in a loop and bridge each one to the agent via a
    /// new QUIC bi-stream (multiplexed over the single QUIC connection).
    pub async fn run(&mut self) -> anyhow::Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.public_port)).await?;
        info!(
            "Tunnel LIVE  :{} -> agent :{}",
            self.public_port, self.local_port
        );

        loop {
            let (player, addr) = listener.accept().await?;
            info!("Player {} connected", addr);

            self.stream_counter += 1;
            let stream_id = self.stream_counter;

            // Notify the agent over the control channel
            send_msg(
                &mut self.ctrl_send,
                &ControlMessage::NewConnection { stream_id },
            )
            .await?;

            // Open a new QUIC bi-stream for this player's data
            let quic = self.quic.clone();
            tokio::spawn(async move {
                match quic.open_bi().await {
                    Ok((quic_send, quic_recv)) => {
                        if let Err(e) =
                            bridge::bridge_tcp_to_quic(player, quic_send, quic_recv, addr).await
                        {
                            error!("Player {} bridge error: {}", addr, e);
                        }
                    }
                    Err(e) => {
                        error!("Failed to open QUIC stream for player {}: {}", addr, e);
                    }
                }
                info!("Player {} disconnected", addr);
            });
        }
    }

    /// Remove this tunnel from the registry.
    pub async fn cleanup(&self) {
        self.state.lock().await.remove(self.public_port);
        info!("Tunnel on port {} cleaned up", self.public_port);
    }
}
