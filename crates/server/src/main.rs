mod bridge;
mod relay;
mod state;
mod tunnel;

use relay::RelayServer;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let server = RelayServer::bind("0.0.0.0:5000").await?;
    server.run().await
}
