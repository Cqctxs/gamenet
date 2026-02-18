use quinn::{RecvStream, SendStream};
use tokio::io::copy;
use tokio::net::TcpStream;
use tracing::{error, info};

/// Bridge a QUIC bi-stream (from the server) to the local game server.
pub async fn bridge_to_local(
    mut quic_send: SendStream,
    mut quic_recv: RecvStream,
    local_port: u16,
) -> anyhow::Result<()> {
    let local_addr = format!("127.0.0.1:{}", local_port);
    let tcp = TcpStream::connect(&local_addr).await?;
    info!("Bridge established: QUIC stream <-> {}", local_addr);

    let (mut tcp_read, mut tcp_write) = tcp.into_split();

    let up = tokio::spawn(async move { copy(&mut quic_recv, &mut tcp_write).await });
    let down = tokio::spawn(async move { copy(&mut tcp_read, &mut quic_send).await });

    tokio::select! {
        r = up => {
            if let Err(e) = r? { error!("Upstream error: {}", e); }
        }
        r = down => {
            if let Err(e) = r? { error!("Downstream error: {}", e); }
        }
    }
    info!("Bridge to {} closed", local_addr);
    Ok(())
}
