use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let public_port = 8080;
    let target_addr = "127.0.0.1:7878";

    let listener = TcpListener::bind(format!("0.0.0.0:{}", public_port)).await?;
    info!("Relay Server: Listening on public port {}", public_port);
    info!("Relay Server: Forwarding to target {}", target_addr);

    loop {
        let (mut public_stream, addr) = listener.accept().await?;
        info!("New player connection from {}", addr);

        tokio::spawn(async move {
            match TcpStream::connect(target_addr).await {
                Ok(mut target_stream) => {
                    info!("Successfully connected to target agent. Bridging bytes...");

                    // This is the core of Feature B in our architecture.
                    // It pumps bytes in both directions:
                    // Player <-> Server <-> Agent
                    if let Err(e) = copy_bidirectional(&mut public_stream, &mut target_stream).await
                    {
                        error!("Bridge error: {}", e);
                    }
                }
                Err(e) => {
                    error!("Could not connect to target agent: {}", e);
                }
            }
            info!("Connection from {} closed.", addr);
        });
    }
}
