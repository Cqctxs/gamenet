use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use gamenet_core::message::{recv_msg, send_msg};
use gamenet_core::protocol::{ControlMessage, Protocol};
use quinn::{Connection, SendStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};
use tokio::task::JoinSet;
use tracing::{error, info, warn};

use crate::bridge;
use crate::lease::{SessionId, TokenId};
use crate::state::{ServerState, now_ms};

const MAX_CONCURRENT_PLAYERS: usize = 50;

/// Ensures a canceled registration cannot leave an active lease behind.
struct PendingRegistration {
    state: Arc<Mutex<ServerState>>,
    token_id: TokenId,
    session_id: SessionId,
    armed: bool,
}

impl PendingRegistration {
    fn new(state: Arc<Mutex<ServerState>>, token_id: TokenId, session_id: SessionId) -> Self {
        Self {
            state,
            token_id,
            session_id,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingRegistration {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let (state, token_id, session_id) =
            (Arc::clone(&self.state), self.token_id, self.session_id);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                if let Err(error) = state.lock().await.end(token_id, session_id, now_ms()) {
                    error!("Failed to clean up canceled registration: {error}");
                }
            });
        } else {
            error!(
                "Registration canceled after runtime shutdown; lease will expire from saved state"
            );
        }
    }
}

pub struct Tunnel {
    quic: Connection,
    ctrl_send: SendStream,
    state: Arc<Mutex<ServerState>>,
    listener: Option<TcpListener>,
    public_port: u16,
    local_port: u16,
    peer_ip: IpAddr,
    token_id: TokenId,
    session_id: SessionId,
    stream_counter: u64,
    player_slots: Arc<Semaphore>,
    global_players: Arc<Semaphore>,
    players: JoinSet<()>,
}

impl Tunnel {
    pub async fn from_quic(
        conn: Connection,
        state: Arc<Mutex<ServerState>>,
        peer_ip: IpAddr,
        global_players: Arc<Semaphore>,
    ) -> anyhow::Result<Self> {
        let (mut ctrl_send, mut ctrl_recv) = conn.accept_bi().await?;
        let msg = recv_msg(&mut ctrl_recv)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Agent disconnected before registering"))?;
        let ControlMessage::Register {
            protocol,
            local_port,
            token,
        } = msg
        else {
            anyhow::bail!("Expected Register as first control message");
        };
        if protocol != Protocol::Tcp || local_port == 0 {
            let reason = "Only TCP tunnels with a nonzero local port are supported";
            send_registration_error(&mut ctrl_send, reason).await;
            anyhow::bail!("{reason}");
        }

        let registration = match state.lock().await.register(token, peer_ip, now_ms()).await {
            Ok(registration) => registration,
            Err(error) => {
                send_registration_error(&mut ctrl_send, &error.to_string()).await;
                return Err(error);
            }
        };
        let mut pending = PendingRegistration::new(
            Arc::clone(&state),
            registration.token_id,
            registration.session_id,
        );
        if let Err(error) = send_msg(
            &mut ctrl_send,
            &ControlMessage::TunnelReady {
                public_port: registration.public_port,
            },
        )
        .await
        {
            drop(registration.listener);
            return Err(error);
        }
        pending.disarm();
        info!(
            "Tunnel registered: public :{} -> agent :{} (peer {})",
            registration.public_port, local_port, peer_ip
        );
        Ok(Self {
            quic: conn,
            ctrl_send,
            state,
            listener: Some(registration.listener),
            public_port: registration.public_port,
            local_port,
            peer_ip,
            token_id: registration.token_id,
            session_id: registration.session_id,
            stream_counter: 0,
            player_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_PLAYERS)),
            global_players,
            players: JoinSet::new(),
        })
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        info!(
            "Tunnel live :{} -> agent :{}",
            self.public_port, self.local_port
        );
        let result = self.accept_players().await;
        self.listener.take();
        self.players.abort_all();
        while self.players.join_next().await.is_some() {}
        result
    }

    async fn accept_players(&mut self) -> anyhow::Result<()> {
        loop {
            let listener = self
                .listener
                .as_ref()
                .expect("listener exists while tunnel runs");
            tokio::select! {
                reason = self.quic.closed() => {
                    info!("Agent {} disconnected: {}", self.peer_ip, reason);
                    return Ok(());
                }
                accepted = listener.accept() => {
                    let (player, address) = accepted?;
                    self.accept_player(player, address).await?;
                }
                completed = self.players.join_next(), if !self.players.is_empty() => {
                    if let Some(Err(error)) = completed {
                        warn!("Player task failed: {error}");
                    }
                }
            }
        }
    }

    async fn accept_player(
        &mut self,
        player: TcpStream,
        address: std::net::SocketAddr,
    ) -> anyhow::Result<()> {
        let local_permit = match Arc::clone(&self.player_slots).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                warn!("Player {address} rejected: tunnel at player limit");
                return Ok(());
            }
        };
        let global_permit = match Arc::clone(&self.global_players).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                warn!("Player {address} rejected: relay at player limit");
                return Ok(());
            }
        };
        self.stream_counter = self.stream_counter.saturating_add(1);
        send_msg(
            &mut self.ctrl_send,
            &ControlMessage::NewConnection {
                stream_id: self.stream_counter,
            },
        )
        .await?;
        let quic = self.quic.clone();
        self.players.spawn(async move {
            let _permits = (local_permit, global_permit);
            match quic.open_bi().await {
                Ok((quic_send, quic_recv)) => {
                    if let Err(error) =
                        bridge::bridge_tcp_to_quic(player, quic_send, quic_recv, address).await
                    {
                        error!("Player {address} bridge error: {error}");
                    }
                }
                Err(error) => error!("Player {address} QUIC stream error: {error}"),
            }
        });
        Ok(())
    }

    pub async fn cleanup(&self) -> anyhow::Result<()> {
        self.state
            .lock()
            .await
            .end(self.token_id, self.session_id, now_ms())?;
        info!(
            "Tunnel on port {} released (peer {})",
            self.public_port, self.peer_ip
        );
        Ok(())
    }
}

async fn send_registration_error(stream: &mut SendStream, message: &str) {
    if send_msg(
        stream,
        &ControlMessage::Error {
            message: message.into(),
        },
    )
    .await
    .is_ok()
    {
        let _ = stream.finish();
        let _ = tokio::time::timeout(Duration::from_secs(1), stream.stopped()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn canceled_registration_releases_active_lease() {
        let _port_guard = crate::state::PORT_TEST_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(Mutex::new(
            ServerState::load_or_new(&dir.path().join("state.json"), 1_000).unwrap(),
        ));
        let registration = state
            .lock()
            .await
            .register([33; 32], "192.0.2.1".parse().unwrap(), 1_000)
            .await
            .unwrap();
        let token_id = registration.token_id;
        let pending =
            PendingRegistration::new(Arc::clone(&state), token_id, registration.session_id);
        drop(registration.listener);
        drop(pending);
        tokio::time::timeout(Duration::from_secs(2), async {
            while state.lock().await.leases.active_session(token_id).is_some() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
}
