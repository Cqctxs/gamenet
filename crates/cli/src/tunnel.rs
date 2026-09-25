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

        // SNI must be the hostname, not the IP, for cert validation to work
        let connecting = endpoint.connect(resolved, server_hostname)?;

        let quic = connecting.await?;
        info!("QUIC connection established to {}", server_hostname);

        let (mut ctrl_send, mut ctrl_recv) = quic.open_bi().await?;

        send_msg(
            &mut ctrl_send,
            &ControlMessage::Register {
                protocol: Protocol::Tcp,
                local_port,
                token,
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
    use super::next_retry_delay;
    use gamenet_core::identity;
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
}
