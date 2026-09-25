use crate::bridge;
use gamenet_core::crypto;
use gamenet_core::identity;
use gamenet_core::message::{recv_msg, send_msg};
use gamenet_core::protocol::{ControlMessage, Protocol};
use quinn::{Connection, Endpoint};
use std::time::Duration;
use tokio::task::{JoinHandle, JoinSet};
use tracing::{error, info};

pub struct AgentTunnel {
    quic: Connection,
    local_port: u16,
    control_task: JoinHandle<()>,
    players: JoinSet<()>,
}

pub fn next_retry_delay(delay: Duration) -> Duration {
    delay.saturating_mul(2).min(Duration::from_secs(15))
}

pub async fn rotate_identity(server_hostname: &str, insecure: bool) -> anyhow::Result<Option<u16>> {
    let pending = identity::prepare_rotation()?;
    let quic = connect_quic(server_hostname, insecure).await?;
    rotate_on_connection(&quic, pending).await
}

pub async fn recover_identity(
    server_hostname: &str,
    insecure: bool,
    use_backup_code: bool,
) -> anyhow::Result<u16> {
    let (secret, from_backup) = if use_backup_code {
        (
            identity::parse_recovery_code(&rpassword::prompt_password("Recovery code: ")?)?,
            true,
        )
    } else {
        match identity::read_recovery() {
            Ok(secret) => (secret, false),
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                (
                    identity::parse_recovery_code(&rpassword::prompt_password("Recovery code: ")?)?,
                    true,
                )
            }
            Err(error) => return Err(error),
        }
    };
    let pending = identity::prepare_recovery()?;
    let quic = connect_quic(server_hostname, insecure).await?;
    recover_on_connection(&quic, pending, secret, from_backup).await
}

async fn recover_on_connection(
    quic: &Connection,
    pending: identity::PendingRecovery,
    secret: identity::TunnelToken,
    from_backup: bool,
) -> anyhow::Result<u16> {
    let (mut send, mut receive) = quic.open_bi().await?;
    send_msg(
        &mut send,
        &ControlMessage::RecoverIdentity {
            recovery_secret: secret,
            new_token: pending.new_token(),
        },
    )
    .await?;
    let response = recv_msg(&mut receive)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Relay closed before confirming recovery"))?;
    match response {
        ControlMessage::IdentityRecovered { public_port } => {
            if from_backup {
                identity::store_recovery(&secret)?;
            }
            pending.finish()?;
            Ok(public_port)
        }
        ControlMessage::Error { message } => anyhow::bail!("Relay rejected recovery: {message}"),
        other => anyhow::bail!("Unexpected recovery response: {other:?}"),
    }
}

async fn rotate_on_connection(
    quic: &Connection,
    pending: identity::PendingRotation,
) -> anyhow::Result<Option<u16>> {
    let (mut send, mut receive) = quic.open_bi().await?;
    send_msg(
        &mut send,
        &ControlMessage::RotateIdentity {
            old_token: pending.old_token(),
            new_token: pending.new_token(),
        },
    )
    .await?;
    let response = recv_msg(&mut receive)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Relay closed before confirming identity rotation"))?;
    match response {
        ControlMessage::IdentityRotated { public_port } => {
            pending.finish()?;
            Ok(public_port)
        }
        ControlMessage::Error { message } => anyhow::bail!("Relay rejected rotation: {message}"),
        other => anyhow::bail!("Unexpected rotation response: {other:?}"),
    }
}

async fn connect_quic(server_hostname: &str, insecure: bool) -> anyhow::Result<Connection> {
    let client_config = if insecure {
        crypto::insecure_client_config()?
    } else {
        crypto::client_config()?
    };
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(client_config);
    let server_addr = format!("{}:5000", server_hostname);
    let resolved: std::net::SocketAddr = match server_addr.parse() {
        Ok(addr) => addr,
        Err(_) => tokio::net::lookup_host(&server_addr)
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("Could not resolve {}", server_addr))?,
    };
    info!("Connecting to {} ({})", server_hostname, resolved);
    let quic = endpoint.connect(resolved, server_hostname)?.await?;
    info!("QUIC connection established to {}", server_hostname);
    Ok(quic)
}

impl AgentTunnel {
    /// Connect to the relay server.
    ///
    /// `server_hostname` is used both for DNS resolution and as the TLS SNI
    /// name, so it must match the server's certificate (e.g. `relay.0verclock.tech`).
    /// Set `insecure = true` only for local development against a self-signed cert.
    pub async fn connect(
        server_hostname: &str,
        local_port: u16,
        insecure: bool,
    ) -> anyhow::Result<Self> {
        let token = identity::load_or_create()?;
        let recovery_secret = identity::load_or_create_recovery()?;

        let quic = connect_quic(server_hostname, insecure).await?;

        let (mut ctrl_send, mut ctrl_recv) = quic.open_bi().await?;

        send_msg(
            &mut ctrl_send,
            &ControlMessage::Register {
                protocol: Protocol::Tcp,
                local_port,
                token,
                recovery_id: identity::recovery_fingerprint(&recovery_secret),
            },
        )
        .await?;

        let msg = recv_msg(&mut ctrl_recv)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Server closed before confirming tunnel"))?;

        match msg {
            ControlMessage::TunnelReady { public_port } => {
                info!("===========================================");
                info!("  TUNNEL IS LIVE!");
                info!("  Tell players to connect to:");
                info!("    {}:{}", server_hostname, public_port);
                info!("  (Reconnections keep this port for up to five minutes)");
                info!("===========================================");
            }
            ControlMessage::Error { message } => {
                anyhow::bail!("Server rejected registration: {}", message);
            }
            other => {
                anyhow::bail!("Unexpected response: {:?}", other);
            }
        }

        let control_task = tokio::spawn(async move {
            if let Err(e) = Self::handle_control_messages(ctrl_recv).await {
                error!("Control channel error: {}", e);
            }
        });

        Ok(Self {
            quic,
            local_port,
            control_task,
            players: JoinSet::new(),
        })
    }

    async fn handle_control_messages(mut ctrl_recv: quinn::RecvStream) -> anyhow::Result<()> {
        loop {
            match recv_msg(&mut ctrl_recv).await? {
                Some(ControlMessage::NewConnection { stream_id }) => {
                    info!("Player #{} joined! Accepting QUIC stream...", stream_id);
                }
                Some(_) => {}
                None => {
                    info!("Control channel closed by server.");
                    break;
                }
            }
        }
        Ok(())
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        loop {
            tokio::select! {
                streams = self.quic.accept_bi() => {
                    match streams {
                        Ok((quic_send, quic_recv)) => {
                            let local_port = self.local_port;
                            self.players.spawn(async move {
                                if let Err(e) = bridge::bridge_to_local(quic_send, quic_recv, local_port).await {
                                    error!("Bridge error: {}", e);
                                }
                            });
                        }
                        Err(error) => {
                            info!("Relay connection closed: {error}");
                            break;
                        }
                    }
                }
                _ = &mut self.control_task => {
                    info!("Relay control channel closed");
                    break;
                }
                completed = self.players.join_next(), if !self.players.is_empty() => {
                    if let Some(Err(error)) = completed {
                        error!("Player task failed: {error}");
                    }
                }
            }
        }
        self.quic.close(0u8.into(), b"reconnecting");
        self.control_task.abort();
        self.players.abort_all();
        while self.players.join_next().await.is_some() {}
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{next_retry_delay, recover_on_connection, rotate_on_connection};
    use gamenet_core::identity;
    use gamenet_core::protocol::ControlMessage;
    use std::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn identity_is_stable_across_calls() {
        let ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let path = std::env::temp_dir().join(format!("cli-id-{}.bin", ns));
        let t1 = identity::load_or_create_at(&path).unwrap();
        let t2 = identity::load_or_create_at(&path).unwrap();
        assert_eq!(t1, t2);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn verified_client_config_builds() {
        assert!(gamenet_core::crypto::client_config().is_ok());
    }

    #[test]
    fn reconnect_delay_caps_at_fifteen_seconds() {
        let mut delay = std::time::Duration::from_secs(1);
        let mut seconds = Vec::new();
        for _ in 0..6 {
            seconds.push(delay.as_secs());
            delay = next_retry_delay(delay);
        }
        assert_eq!(seconds, vec![1, 2, 4, 8, 15, 15]);
    }

    #[tokio::test]
    async fn recovery_installs_replacement_only_after_relay_ack() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.bin");
        let old = identity::load_or_create_at(&path).unwrap();
        let pending = identity::prepare_recovery_at(&path).unwrap();
        let new = pending.new_token();
        let secret = [99; 32];
        let (config, _) = gamenet_core::crypto::server_config().unwrap();
        let server = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let address = server.local_addr().unwrap();
        let server_identity_path = path.clone();
        let server_task = tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            let (mut send, mut receive) = connection.accept_bi().await.unwrap();
            let request = gamenet_core::message::recv_msg(&mut receive)
                .await
                .unwrap()
                .unwrap();
            assert!(
                matches!(request, ControlMessage::RecoverIdentity { recovery_secret, new_token } if recovery_secret == secret && new_token == new)
            );
            assert_eq!(
                identity::load_or_create_at(&server_identity_path).unwrap(),
                old
            );
            gamenet_core::message::send_msg(
                &mut send,
                &ControlMessage::IdentityRecovered { public_port: 10042 },
            )
            .await
            .unwrap();
            send.finish().unwrap();
            send.stopped().await.unwrap();
        });
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(gamenet_core::crypto::insecure_client_config().unwrap());
        let connection = client.connect(address, "localhost").unwrap().await.unwrap();
        let port = tokio::time::timeout(
            Duration::from_secs(3),
            recover_on_connection(&connection, pending, secret, false),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(port, 10042);
        server_task.await.unwrap();
        assert_eq!(identity::load_or_create_at(&path).unwrap(), new);
    }

    #[tokio::test]
    async fn rotation_installs_new_identity_only_after_relay_ack() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.bin");
        let old = identity::load_or_create_at(&path).unwrap();
        let pending = identity::prepare_rotation_at(&path).unwrap();
        let new = pending.new_token();

        let (config, _) = gamenet_core::crypto::server_config().unwrap();
        let server = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let address = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            let (mut send, mut receive) = connection.accept_bi().await.unwrap();
            let request = gamenet_core::message::recv_msg(&mut receive)
                .await
                .unwrap()
                .unwrap();
            assert!(
                matches!(request, ControlMessage::RotateIdentity { old_token, new_token } if old_token == old && new_token == new)
            );
            gamenet_core::message::send_msg(
                &mut send,
                &ControlMessage::IdentityRotated {
                    public_port: Some(10042),
                },
            )
            .await
            .unwrap();
            send.finish().unwrap();
            send.stopped().await.unwrap();
        });
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(gamenet_core::crypto::insecure_client_config().unwrap());
        let connection = client.connect(address, "localhost").unwrap().await.unwrap();
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            rotate_on_connection(&connection, pending),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(result, Some(10042));
        assert_eq!(identity::load_or_create_at(&path).unwrap(), new);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn rejected_rotation_keeps_old_identity_and_pending_retry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("identity.bin");
        let old = identity::load_or_create_at(&path).unwrap();
        let pending = identity::prepare_rotation_at(&path).unwrap();
        let new = pending.new_token();

        let (config, _) = gamenet_core::crypto::server_config().unwrap();
        let server = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let address = server.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let connection = server.accept().await.unwrap().await.unwrap();
            let (mut send, mut receive) = connection.accept_bi().await.unwrap();
            let request = gamenet_core::message::recv_msg(&mut receive)
                .await
                .unwrap()
                .unwrap();
            assert!(matches!(request, ControlMessage::RotateIdentity { .. }));
            gamenet_core::message::send_msg(
                &mut send,
                &ControlMessage::Error {
                    message: "Host is still active".into(),
                },
            )
            .await
            .unwrap();
            send.finish().unwrap();
            send.stopped().await.unwrap();
        });
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(gamenet_core::crypto::insecure_client_config().unwrap());
        let connection = client.connect(address, "localhost").unwrap().await.unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_secs(3),
                rotate_on_connection(&connection, pending),
            )
            .await
            .unwrap()
            .is_err()
        );
        assert_eq!(identity::load_or_create_at(&path).unwrap(), old);
        assert_eq!(
            identity::prepare_rotation_at(&path).unwrap().new_token(),
            new
        );
        server_task.await.unwrap();
    }
}
