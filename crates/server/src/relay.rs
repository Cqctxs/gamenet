use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use quinn::{Endpoint, ServerConfig};
use tokio::sync::{Mutex, Semaphore};
use tokio::time::{self, MissedTickBehavior};
use tracing::{error, info, warn};

use crate::host_admission::PendingByIp;
use crate::state::{ServerState, now_ms};
use crate::tunnel::Tunnel;

const PENDING_LIMIT: usize = 128;
const PENDING_PER_IP_LIMIT: usize = 4;
const GLOBAL_PLAYER_LIMIT: usize = 2000;
const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(10);

fn tls_server_config(
    cert_path: Option<&Path>,
    key_path: Option<&Path>,
    development_self_signed: bool,
) -> anyhow::Result<ServerConfig> {
    match (cert_path, key_path) {
        (Some(cert), Some(key)) => {
            info!("Loading TLS cert from {}", cert.display());
            gamenet_core::crypto::server_config_from_files(cert, key)
        }
        (None, None) if development_self_signed => {
            warn!("Using a self-signed development certificate");
            Ok(gamenet_core::crypto::server_config()?.0)
        }
        (None, None) => anyhow::bail!(
            "Set GAMENET_TLS_CERT and GAMENET_TLS_KEY for production, or GAMENET_DEV_SELF_SIGNED=1 for local development"
        ),
        _ => anyhow::bail!("GAMENET_TLS_CERT and GAMENET_TLS_KEY must both be set"),
    }
}

pub struct RelayServer {
    state: Arc<Mutex<ServerState>>,
    endpoint: Endpoint,
    pending: Arc<Semaphore>,
    pending_by_ip: Arc<PendingByIp>,
    global_players: Arc<Semaphore>,
}

impl RelayServer {
    pub async fn bind(addr: &str) -> anyhow::Result<Self> {
        let cert_path = std::env::var_os("GAMENET_TLS_CERT").map(PathBuf::from);
        let key_path = std::env::var_os("GAMENET_TLS_KEY").map(PathBuf::from);
        let development_self_signed =
            std::env::var("GAMENET_DEV_SELF_SIGNED").as_deref() == Ok("1");
        let config = tls_server_config(
            cert_path.as_deref(),
            key_path.as_deref(),
            development_self_signed,
        )?;
        Self::bind_with_config_and_state_path(addr, Path::new("./gamenet-state.json"), config).await
    }

    #[cfg(test)]
    pub async fn bind_with_state_path(addr: &str, state_path: &Path) -> anyhow::Result<Self> {
        let config = tls_server_config(None, None, true)?;
        Self::bind_with_config_and_state_path(addr, state_path, config).await
    }

    async fn bind_with_config_and_state_path(
        addr: &str,
        state_path: &Path,
        server_config: ServerConfig,
    ) -> anyhow::Result<Self> {
        let state = ServerState::load_or_new(state_path, now_ms())?;
        let endpoint = Endpoint::server(server_config, addr.parse()?)?;
        info!("QUIC relay server listening on {}", endpoint.local_addr()?);
        Ok(Self {
            state: Arc::new(Mutex::new(state)),
            endpoint,
            pending: Arc::new(Semaphore::new(PENDING_LIMIT)),
            pending_by_ip: Arc::new(PendingByIp::new(PENDING_PER_IP_LIMIT)),
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
                    let Some(ip_permit) = self.pending_by_ip.try_acquire(address.ip()) else {
                        incoming.refuse();
                        continue;
                    };
                    let state = Arc::clone(&self.state);
                    let players = Arc::clone(&self.global_players);
                    tokio::spawn(async move {
                        let registration = time::timeout(REGISTRATION_TIMEOUT, async {
                            let connection = incoming.accept()?.await?;
                            Tunnel::from_quic(connection, state, address.ip(), players).await
                        }).await;
                        drop((permit, ip_permit));
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

    #[test]
    fn production_tls_requires_a_complete_certificate_pair() {
        let missing = Path::new("/nonexistent/gamenet.pem");
        assert!(tls_server_config(None, None, false).is_err());
        assert!(tls_server_config(Some(missing), None, false).is_err());
        assert!(tls_server_config(None, Some(missing), false).is_err());
        assert!(tls_server_config(Some(missing), Some(missing), false).is_err());
        assert!(tls_server_config(Some(missing), None, true).is_err());
        assert!(tls_server_config(None, None, true).is_ok());
    }

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
    async fn third_idle_host_from_one_ip_cannot_reserve_a_port() {
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

        let (first, _, first_response) = register(&endpoint, address, [21; 32], Protocol::Tcp)
            .await
            .unwrap();
        let (second, _, second_response) = register(&endpoint, address, [22; 32], Protocol::Tcp)
            .await
            .unwrap();
        assert!(matches!(first_response, ControlMessage::TunnelReady { .. }));
        assert!(matches!(
            second_response,
            ControlMessage::TunnelReady { .. }
        ));
        let (_, _, third_response) = register(&endpoint, address, [23; 32], Protocol::Tcp)
            .await
            .unwrap();
        assert!(
            matches!(third_response, ControlMessage::Error { message } if message.contains("Too many tunnels"))
        );
        first.close(0u8.into(), b"test shutdown");
        second.close(0u8.into(), b"test shutdown");
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

    #[tokio::test]
    async fn one_host_ip_cannot_fill_all_pending_registration_slots() {
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

        let mut idle = Vec::new();
        for _ in 0..PENDING_PER_IP_LIMIT {
            idle.push(
                endpoint
                    .connect(address, "localhost")
                    .unwrap()
                    .await
                    .unwrap(),
            );
        }
        let ip = "127.0.0.1".parse().unwrap();
        assert_eq!(server.pending_by_ip.active_for(ip), PENDING_PER_IP_LIMIT);
        assert_eq!(
            server.pending.available_permits(),
            PENDING_LIMIT - PENDING_PER_IP_LIMIT
        );
        let refused = tokio::time::timeout(
            Duration::from_secs(2),
            endpoint.connect(address, "localhost").unwrap(),
        )
        .await;
        assert!(!matches!(refused, Ok(Ok(_))));

        idle.pop().unwrap().close(0u8.into(), b"test disconnect");
        tokio::time::timeout(Duration::from_secs(2), async {
            while server.pending_by_ip.active_for(ip) != PENDING_PER_IP_LIMIT - 1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let resumed = endpoint.connect(address, "localhost").unwrap().await;
        assert!(resumed.is_ok());
        server.close();
        task.await.unwrap().unwrap();
    }
}
