use gamenet_core::bridge::copy_halves;
use quinn::{RecvStream, SendStream};
use std::net::SocketAddr;
use tokio::net::TcpStream;

/// Bridge a player's TCP connection to a QUIC bi-stream (and vice-versa).
///
/// Data flows in both directions until either side disconnects.
pub async fn bridge_tcp_to_quic(
    tcp: TcpStream,
    quic_send: SendStream,
    quic_recv: RecvStream,
    _player_addr: SocketAddr,
) -> anyhow::Result<()> {
    let (tcp_read, tcp_write) = tcp.into_split();

    copy_halves(tcp_read, tcp_write, quic_recv, quic_send).await?;
    Ok(())
}
