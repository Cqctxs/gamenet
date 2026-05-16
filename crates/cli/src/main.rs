mod bridge;
mod tunnel;

use clap::{Parser, Subcommand};
use gamenet_core::presets;
use tunnel::AgentTunnel;

#[derive(Parser)]
#[command(
    name = "gamenet",
    about = "GameNet — tunnel your local game server to the internet"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Host a game server through the relay
    ///
    /// Supported games: minecraft, bedrock, valheim, terraria, factorio
    Host {
        /// Game name (e.g. "minecraft") or omit and use --port
        game: Option<String>,

        /// Local port to tunnel (overrides game preset)
        #[arg(short, long)]
        port: Option<u16>,

        /// Relay server address (for development/testing)
        #[arg(long, default_value = "localhost", hide = true)]
        server: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Host { game, port, server } => {
            let local_port = match (&game, port) {
                // Explicit --port always wins
                (_, Some(p)) => p,
                // Look up game preset
                (Some(name), None) => {
                    let preset = presets::find_preset(name).ok_or_else(|| {
                        let available: Vec<&str> =
                            presets::PRESETS.iter().map(|p| p.name).collect();
                        anyhow::anyhow!(
                            "Unknown game '{}'. Available: {}\n\
                             Or specify a port directly with: gamenet host --port <PORT>",
                            name,
                            available.join(", ")
                        )
                    })?;
                    println!(
                        "{} — using default port {}",
                        preset.name, preset.default_port
                    );
                    preset.default_port
                }
                // Neither game nor port
                (None, None) => {
                    let available: Vec<&str> = presets::PRESETS.iter().map(|p| p.name).collect();
                    anyhow::bail!(
                        "Please specify a game or port.\n\n\
                         Usage:\n  \
                         gamenet host minecraft\n  \
                         gamenet host --port 7777\n\n\
                         Supported games: {}",
                        available.join(", ")
                    );
                }
            };

            let mut tunnel = AgentTunnel::connect(&server, local_port).await?;
            tunnel.run().await
        }
    }
}
