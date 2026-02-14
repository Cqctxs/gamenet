mod bridge;
mod tunnel;

use clap::Parser;
use tunnel::AgentTunnel;

#[derive(Parser)]
#[command(name = "gamenet", about = "GameNet Tunnel Agent")]
struct Args {
    /// IP address of the GameNet relay server
    #[arg(short, long, default_value = "127.0.0.1")]
    server: String,

    /// Local game port to tunnel (e.g. 25565 for Minecraft)
    #[arg(short, long, default_value_t = 25565)]
    port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let mut tunnel = AgentTunnel::connect(&args.server, args.port).await?;
    tunnel.run().await
}
