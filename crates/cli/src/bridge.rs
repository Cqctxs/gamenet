use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tracing::info;

/// Connect to the server's data port AND the local game, then bridge them.
pub async fn bridge_player(server_data_addr: &str, local_game_addr: &str) -> anyhow::Result<()> {
    let mut server_stream = TcpStream::connect(server_data_addr).await?;
    let mut game_stream = TcpStream::connect(local_game_addr).await?;
    info!("Bridge established: {} <-> {}", server_data_addr, local_game_addr);
    copy_bidirectional(&mut server_stream, &mut game_stream).await?;
    Ok(())
}
