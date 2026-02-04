use tokio::net::{TcpListener, TcpStream};
use tokio::io::copy_bidirectional;
use tracing::{info, error};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let agent_port = 7878;
    let local_game_addr = "127.0.0.1:25565"; // Example: Minecraft

    let listener = TcpListener::bind(format!("127.0.0.1:{}", agent_port)).await?;
    info!("CLI Agent: Listening for relay on port {}", agent_port);

    loop {
        let (mut relay_stream, _) = listener.accept().await?;
        info!("Received connection from relay server.");

        tokio::spawn(async move {
            match TcpStream::connect(local_game_addr).await {
                Ok(mut game_stream) => {
                    info!("Connected to local game. Bridging bytes...");
                    if let Err(e) = copy_bidirectional(&mut relay_stream, &mut game_stream).await {
                        error!("Bridge error: {}", e);
                    }
                }
                Err(e) => {
                    error!("Could not connect to local game (is it running?): {}", e);
                }
            }
        });
    }
}