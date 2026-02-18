use quinn::{RecvStream, SendStream};
use std::net::SocketAddr;
use tokio::io::copy;
use tokio::net::TcpStream;
use tracing::error;

/// Bridge a player's TCP connection to a QUIC bi-stream (and vice-versa).
///
/// Data flows in both directions until either side disconnects.
pub async fn bridge_tcp_to_quic(
    tcp: TcpStream,
    mut quic_send: SendStream,
    mut quic_recv: RecvStream,
    player_addr: SocketAddr,
) -> anyhow::Result<()> {
    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    // Two concurrent copy tasks — QUIC send/recv are separate types
    // so we can't use copy_bidirectional directly.
    let up = tokio::spawn(async move { copy(&mut tcp_read, &mut quic_send).await });
    let down = tokio::spawn(async move { copy(&mut quic_recv, &mut tcp_write).await });

    tokio::select! {
        r = up => {
            if let Err(e) = r? { error!("Player {} upstream error: {}", player_addr, e); }
        }
        r = down => {
            if let Err(e) = r? { error!("Player {} downstream error: {}", player_addr, e); }
        }
    }
    Ok(())
}
