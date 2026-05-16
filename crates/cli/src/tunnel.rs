use crate::bridge;
use gamenet_core::crypto;
use gamenet_core::identity;
use gamenet_core::message::{recv_msg, send_msg};
use gamenet_core::protocol::{ControlMessage, Protocol};
use quinn::{Connection, Endpoint};
use tracing::{error, info};

pub struct AgentTunnel {
    quic: Connection,
    local_port: u16,
}

impl AgentTunnel {
    pub async fn connect(server_ip: &str, local_port: u16) -> anyhow::Result<Self> {
        let token = identity::load_or_create()?;

        let client_config = crypto::insecure_client_config()?;
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_config);

        let server_addr = format!("{}:5000", server_ip);
        let resolved: std::net::SocketAddr = match server_addr.parse() {
            Ok(addr) => addr,
            Err(_) => tokio::net::lookup_host(&server_addr)
                .await?
                .next()
                .ok_or_else(|| anyhow::anyhow!("Could not resolve {}", server_addr))?,
        };
        info!("Connecting to {}", resolved);

        let connecting = endpoint.connect(resolved, "localhost")?;
        let quic = match connecting.into_0rtt() {
            Ok((conn, zero_rtt_accepted)) => {
                info!("0-RTT connection attempt to {}", server_addr);
                tokio::spawn(async move {
                    if zero_rtt_accepted.await {
                        info!("Server accepted 0-RTT data");
                    } else {
                        info!("Server rejected 0-RTT (fell back to 1-RTT)");
                    }
                });
                conn
            }
            Err(connecting) => {
                info!("Full QUIC handshake to {}", server_addr);
                connecting.await?
            }
        };
        info!("QUIC connection established to {}", server_addr);

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
                info!("    {}:{}", server_ip, public_port);
                info!("  (This port is permanently yours — share it once)");
                info!("===========================================");
            }
            ControlMessage::Error { message } => {
                anyhow::bail!("Server rejected registration: {}", message);
            }
            other => {
                anyhow::bail!("Unexpected response: {:?}", other);
            }
        }

        tokio::spawn(async move {
            if let Err(e) = Self::handle_control_messages(ctrl_recv).await {
                error!("Control channel error: {}", e);
            }
        });

        Ok(Self { quic, local_port })
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

#[cfg(test)]
mod tests {
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
}
