use gamenet_core::bridge::copy_halves;
use quinn::{RecvStream, SendStream};
use tokio::net::TcpStream;
use tracing::info;

/// Bridge a QUIC bi-stream (from the server) to the local game server.
pub async fn bridge_to_local(
    quic_send: SendStream,
    quic_recv: RecvStream,
    local_port: u16,
) -> anyhow::Result<()> {
    let local_addr = format!("127.0.0.1:{}", local_port);
    let tcp = TcpStream::connect(&local_addr).await?;
    info!("Bridge established: QUIC stream <-> {}", local_addr);

    let (tcp_read, tcp_write) = tcp.into_split();

    copy_halves(tcp_read, tcp_write, quic_recv, quic_send).await?;
    info!("Bridge to {} closed", local_addr);
    Ok(())
}
