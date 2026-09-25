use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use quinn::Endpoint;
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{self, MissedTickBehavior};
use tracing::{error, info, warn};

use crate::state::{ServerState, now_ms};
use crate::tunnel::Tunnel;

const PENDING_LIMIT: usize = 128;
const GLOBAL_PLAYER_LIMIT: usize = 2000;
const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(10);

pub struct RelayServer {
    state: Arc<Mutex<ServerState>>,
    endpoint: Endpoint,
    pending: Arc<Semaphore>,
    global_players: Arc<Semaphore>,
}

impl RelayServer {
    pub async fn bind(addr: &str) -> anyhow::Result<Self> {
        Self::bind_with_state_path(addr, Path::new("./gamenet-state.json")).await
    }

    pub async fn bind_with_state_path(addr: &str, state_path: &Path) -> anyhow::Result<Self> {
        let server_config = match (
            std::env::var("GAMENET_TLS_CERT"),
            std::env::var("GAMENET_TLS_KEY"),
        ) {
            (Ok(cert_path), Ok(key_path)) => {
                info!("Loading TLS cert from {}", cert_path);
                gamenet_core::crypto::server_config_from_files(
                    Path::new(&cert_path),
                    Path::new(&key_path),
                )?
            }
            _ => {
                warn!(
                    "TLS certificate/key not both set; using self-signed development certificate"
                );
                gamenet_core::crypto::server_config()?.0
            }
        };
        let state = ServerState::load_or_new(state_path, now_ms())?;
        let endpoint = Endpoint::server(server_config, addr.parse()?)?;
        info!("QUIC relay server listening on {}", endpoint.local_addr()?);
        Ok(Self {
            state: Arc::new(Mutex::new(state)),
            endpoint,
            pending: Arc::new(Semaphore::new(PENDING_LIMIT)),
            global_players: Arc::new(Semaphore::new(GLOBAL_PLAYER_LIMIT)),
        })
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let mut refresh = time::interval(Duration::from_secs(30));
        refresh.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = refresh.tick() => {
                    if let Err(error) = self.state.lock().await.refresh_and_save(now_ms()) {
                        error!("Lease persistence failed; new registrations blocked: {error}");
                    }
                }
                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else { return Ok(()); };
                    let address = incoming.remote_address();
                    let permit = match Arc::clone(&self.pending).try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            incoming.refuse();
                            continue;
                        }
                    };
                    let state = Arc::clone(&self.state);
                    let players = Arc::clone(&self.global_players);
                    tokio::spawn(async move {
                        let registration = time::timeout(REGISTRATION_TIMEOUT, async {
                            let connection = incoming.accept()?.await?;
                            Tunnel::from_quic(connection, state, address.ip(), players).await
                        }).await;
                        drop(permit);
                        match registration {
                            Ok(Ok(mut tunnel)) => {
                                if let Err(error) = tunnel.run().await {
                                    error!("Agent {address} tunnel error: {error}");
                                }
                                if let Err(error) = tunnel.cleanup().await {
                                    error!("Agent {address} cleanup error: {error}");
                                }
                            }
                            Ok(Err(error)) => warn!("Agent {address} failed to register: {error}"),
                            Err(_) => warn!("Agent {address} registration timed out"),
                        }
                    });
                }
            }
        }
    }

    #[cfg(test)]
    pub fn local_addr(&self) -> anyhow::Result<std::net::SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }

    #[cfg(test)]
    pub fn close(&self) {
        self.endpoint.close(0u8.into(), b"test shutdown");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gamenet_core::message::{recv_msg, send_msg};
    use gamenet_core::protocol::{ControlMessage, Protocol};
    use quinn::{Connection, Endpoint};

    async fn register(
        endpoint: &Endpoint,
        address: std::net::SocketAddr,
        token: [u8; 32],
        protocol: Protocol,
    ) -> anyhow::Result<(Connection, quinn::RecvStream, ControlMessage)> {
        let connection = endpoint.connect(address, "localhost")?.await?;
        let (mut send, mut receive) = connection.open_bi().await?;
        send_msg(
            &mut send,
            &ControlMessage::Register {
                protocol,
                local_port: 25565,
                token,
            },
        )
        .await?;
        let response = recv_msg(&mut receive)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Missing response"))?;
        Ok((connection, receive, response))
    }

    #[tokio::test]
    async fn registration_is_bound_and_duplicate_identity_is_rejected() {
        let _port_guard = crate::state::PORT_TEST_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let server = Arc::new(
            RelayServer::bind_with_state_path("127.0.0.1:0", &dir.path().join("state.json"))
                .await
                .unwrap(),
        );
        let address = server.local_addr().unwrap();
        let running = Arc::clone(&server);
        let task = tokio::spawn(async move { running.run().await });

        let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(gamenet_core::crypto::insecure_client_config().unwrap());
        let (first, _control, response) = register(&endpoint, address, [1; 32], Protocol::Tcp)
            .await
            .unwrap();
        let ControlMessage::TunnelReady { public_port } = response else {
            panic!("Expected TunnelReady")
        };
        let connected = tokio::net::TcpStream::connect(("127.0.0.1", public_port)).await;
        assert!(connected.is_ok());
        let (_, _, response) = register(&endpoint, address, [1; 32], Protocol::Tcp)
            .await
            .unwrap();
        assert!(matches!(response, ControlMessage::Error { .. }));
        first.close(0u8.into(), b"test disconnect");
        server.close();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn idle_disconnect_closes_listener_and_preserves_reconnect_port() {
        let _port_guard = crate::state::PORT_TEST_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let server = Arc::new(
            RelayServer::bind_with_state_path("127.0.0.1:0", &dir.path().join("state.json"))
                .await
                .unwrap(),
        );
        let address = server.local_addr().unwrap();
        let running = Arc::clone(&server);
        let task = tokio::spawn(async move { running.run().await });
        let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(gamenet_core::crypto::insecure_client_config().unwrap());
        let (first, _control, response) = register(&endpoint, address, [2; 32], Protocol::Tcp)
            .await
            .unwrap();
        let ControlMessage::TunnelReady { public_port } = response else {
            panic!("Expected TunnelReady")
        };
        first.close(0u8.into(), b"test disconnect");
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if tokio::net::TcpStream::connect(("127.0.0.1", public_port))
                    .await
                    .is_err()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        let (_, _, response) = register(&endpoint, address, [2; 32], Protocol::Tcp)
            .await
            .unwrap();
        assert!(
            matches!(response, ControlMessage::TunnelReady { public_port: same } if same == public_port)
        );
        server.close();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn udp_registration_is_rejected_without_reserving_a_port() {
        let _port_guard = crate::state::PORT_TEST_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let server = Arc::new(
            RelayServer::bind_with_state_path("127.0.0.1:0", &dir.path().join("state.json"))
                .await
                .unwrap(),
        );
        let address = server.local_addr().unwrap();
        let running = Arc::clone(&server);
        let task = tokio::spawn(async move { running.run().await });
        let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(gamenet_core::crypto::insecure_client_config().unwrap());
        let (_, _, response) = register(&endpoint, address, [3; 32], Protocol::Udp)
            .await
            .unwrap();
        assert!(matches!(response, ControlMessage::Error { message } if message.contains("TCP")));
        let (_, _, response) = register(&endpoint, address, [3; 32], Protocol::Tcp)
            .await
            .unwrap();
        assert!(matches!(response, ControlMessage::TunnelReady { .. }));
        server.close();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn global_player_budget_rejects_extra_socket_and_releases_on_disconnect() {
        use tokio::io::AsyncReadExt;

        let _port_guard = crate::state::PORT_TEST_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let mut relay =
            RelayServer::bind_with_state_path("127.0.0.1:0", &dir.path().join("state.json"))
                .await
                .unwrap();
        relay.global_players = Arc::new(Semaphore::new(1));
        let server = Arc::new(relay);
        let address = server.local_addr().unwrap();
        let running = Arc::clone(&server);
        let task = tokio::spawn(async move { running.run().await });
        let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(gamenet_core::crypto::insecure_client_config().unwrap());
        let (agent, _control, response) = register(&endpoint, address, [4; 32], Protocol::Tcp)
            .await
            .unwrap();
        let ControlMessage::TunnelReady { public_port } = response else {
            panic!("Expected TunnelReady")
        };
        let _first_player = tokio::net::TcpStream::connect(("127.0.0.1", public_port))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while server.global_players.available_permits() != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let mut second_player = tokio::net::TcpStream::connect(("127.0.0.1", public_port))
            .await
            .unwrap();
        let mut byte = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(2), second_player.read(&mut byte))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read, 0);
        assert_eq!(server.global_players.available_permits(), 0);
        agent.close(0u8.into(), b"test disconnect");
        tokio::time::timeout(Duration::from_secs(2), async {
            while server.global_players.available_permits() != 1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        server.close();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn pending_registration_limit_and_deadline_release_capacity() {
        let _port_guard = crate::state::PORT_TEST_LOCK.lock().await;
        let dir = tempfile::tempdir().unwrap();
        let mut relay =
            RelayServer::bind_with_state_path("127.0.0.1:0", &dir.path().join("state.json"))
                .await
                .unwrap();
        relay.pending = Arc::new(Semaphore::new(1));
        let server = Arc::new(relay);
        let address = server.local_addr().unwrap();
        let running = Arc::clone(&server);
        let task = tokio::spawn(async move { running.run().await });
        let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(gamenet_core::crypto::insecure_client_config().unwrap());
        let _idle = endpoint
            .connect(address, "localhost")
            .unwrap()
            .await
            .unwrap();
        assert_eq!(server.pending.available_permits(), 0);
        let refused = tokio::time::timeout(
            Duration::from_secs(2),
            endpoint.connect(address, "localhost").unwrap(),
        )
        .await;
        assert!(
            !matches!(refused, Ok(Ok(_))),
            "second pending connection must be refused"
        );
        tokio::time::timeout(Duration::from_secs(12), async {
            while server.pending.available_permits() != 1 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        server.close();
        task.await.unwrap().unwrap();
    }
}
