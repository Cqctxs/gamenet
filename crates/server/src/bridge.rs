use std::net::SocketAddr;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tracing::{error, info};

/// Spawn a background task that bridges two TCP streams.
///
/// All data from `player` is forwarded to `agent` and vice versa.
/// The task runs until either side disconnects.
pub fn spawn_bridge(mut player: TcpStream, mut agent: TcpStream, player_addr: SocketAddr) {
    tokio::spawn(async move {
        if let Err(e) = copy_bidirectional(&mut player, &mut agent).await {
            error!("Bridge for {} closed: {}", player_addr, e);
        }
        info!("Player {} disconnected.", player_addr);
    });
}
