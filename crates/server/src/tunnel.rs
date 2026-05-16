use crate::bridge;
use crate::state::ServerState;
use gamenet_core::message::{recv_msg, send_msg};
use gamenet_core::protocol::ControlMessage;
use quinn::{Connection, SendStream};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

const MAX_CONCURRENT_PLAYERS: usize = 50;

/// One active tunnel between an agent and its players.
///
/// The agent holds a single QUIC connection to the server.
/// The first bi-stream is the control channel.
/// Each new player gets a fresh QUIC bi-stream (multiplexed over the single connection).
pub struct Tunnel {
    quic: Connection,
    ctrl_send: SendStream,
    state: Arc<Mutex<ServerState>>,
    public_port: u16,
    local_port: u16,
    peer_ip: IpAddr,
    stream_counter: u64,
    active_players: Arc<AtomicUsize>,
}

impl Tunnel {
    /// Perform the handshake over the first QUIC bi-stream (control channel).
    pub async fn from_quic(
        conn: Connection,
        state: Arc<Mutex<ServerState>>,
        peer_ip: IpAddr,
    ) -> anyhow::Result<Self> {
        let (mut ctrl_send, mut ctrl_recv) = conn.accept_bi().await?;

        let msg = recv_msg(&mut ctrl_recv)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Agent disconnected before registering"))?;

        let ControlMessage::Register { local_port, token, .. } = msg else {
            warn!("Expected Register, got {:?}", msg);
            anyhow::bail!("Invalid first message");
        };

        let public_port = state
            .lock()
            .await
            .assign_or_resume(token, local_port, peer_ip)?;

        send_msg(&mut ctrl_send, &ControlMessage::TunnelReady { public_port }).await?;
        info!(
            "Tunnel registered: public :{} -> agent :{} (peer {})",
            public_port, local_port, peer_ip
        );

        Ok(Self {
            quic: conn,
            ctrl_send,
            state,
            public_port,
            local_port,
            peer_ip,
            stream_counter: 0,
            active_players: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Accept TCP players in a loop and bridge each one to the agent via a
    /// new QUIC bi-stream (multiplexed over the single QUIC connection).
    pub async fn run(&mut self) -> anyhow::Result<()> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.public_port)).await?;
        info!("Tunnel LIVE  :{} -> agent :{}", self.public_port, self.local_port);

        loop {
            let (player, addr) = listener.accept().await?;

            // Enforce per-tunnel player cap before spawning a task
            let current = self.active_players.fetch_add(1, Ordering::Relaxed);
            if current >= MAX_CONCURRENT_PLAYERS {
                self.active_players.fetch_sub(1, Ordering::Relaxed);
                warn!(
                    "Player {} rejected: tunnel at max {} concurrent players",
                    addr, MAX_CONCURRENT_PLAYERS
                );
                drop(player);
                continue;
            }
            info!("Player {} connected ({}/{})", addr, current + 1, MAX_CONCURRENT_PLAYERS);

            self.stream_counter += 1;
            let stream_id = self.stream_counter;

            send_msg(
                &mut self.ctrl_send,
                &ControlMessage::NewConnection { stream_id },
            )
            .await?;

            let quic = self.quic.clone();
            let players = Arc::clone(&self.active_players);
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
                players.fetch_sub(1, Ordering::Relaxed);
                info!("Player {} disconnected", addr);
            });
        }
    }

    /// Remove this tunnel from the registry (port stays reserved for the token).
    pub async fn cleanup(&self) {
        self.state.lock().await.release(self.public_port);
        info!(
            "Tunnel on port {} released (peer {})",
            self.public_port, self.peer_ip
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn player_counter_saturates_at_max() {
        let counter = Arc::new(AtomicUsize::new(0));
        let max = 50usize;
        for _ in 0..max {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        assert_eq!(counter.load(Ordering::Relaxed), max);
        let current = counter.fetch_add(1, Ordering::Relaxed);
        assert!(current >= max, "should be rejected at or above max");
        counter.fetch_sub(1, Ordering::Relaxed);
        assert_eq!(counter.load(Ordering::Relaxed), max);
    }
}
