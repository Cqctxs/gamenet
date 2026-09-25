mod bridge;
mod tunnel;

use clap::{Parser, Subcommand};
use gamenet_core::presets;
use gamenet_core::protocol::Protocol;
use tracing::warn;
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
    /// Supported TCP games: minecraft, terraria
    Host {
        /// Game name (e.g. "minecraft") or omit and use --port
        game: Option<String>,

        /// Local port to tunnel (overrides game preset)
        #[arg(short, long)]
        port: Option<u16>,

        /// Relay server hostname
        #[arg(long, default_value = "relay.0verclock.tech", hide = true)]
        server: String,

        /// Skip TLS certificate verification (development only)
        #[arg(long, default_value_t = false, hide = true)]
        insecure: bool,
    },
    /// Replace this host's identity after stopping its tunnel
    RotateIdentity {
        /// Relay server hostname
        #[arg(long, default_value = "relay.0verclock.tech", hide = true)]
        server: String,

        /// Skip TLS certificate verification (development only)
        #[arg(long, default_value_t = false, hide = true)]
        insecure: bool,
    },
    /// Print the private recovery code to save in a password manager
    ShowRecoveryCode,
    /// Revoke a stolen identity and transfer its port claim
    RecoverIdentity {
        /// Prompt for the saved backup code even if recovery.bin exists
        #[arg(long)]
        use_backup_code: bool,
        /// Relay server hostname
        #[arg(long, default_value = "relay.0verclock.tech", hide = true)]
        server: String,
        /// Skip TLS certificate verification (development only)
        #[arg(long, default_value_t = false, hide = true)]
        insecure: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::ShowRecoveryCode => {
            let secret = gamenet_core::identity::read_recovery()?;
            println!("{}", gamenet_core::identity::format_recovery_code(&secret));
            Ok(())
        }
        Commands::RecoverIdentity {
            use_backup_code,
            server,
            insecure,
        } => {
            let port = tunnel::recover_identity(&server, insecure, use_backup_code).await?;
            println!(
                "Identity recovered. The old tunnel was revoked. Host again to reclaim {server}:{port}."
            );
            Ok(())
        }
        Commands::RotateIdentity { server, insecure } => {
            let port = tunnel::rotate_identity(&server, insecure).await?;
            match port {
                Some(port) => {
                    println!("Identity rotated. Your next tunnel can reclaim {server}:{port}.")
                }
                None => println!("Identity rotated. The old port claim had already expired."),
            }
            Ok(())
        }
        Commands::Host {
            game,
            port,
            server,
            insecure,
        } => {
            let local_port = local_port_for(game.as_deref(), port)?;
            let mut tunnel = AgentTunnel::connect(&server, local_port, insecure).await?;
            println!("Save your recovery code in a password manager: gamenet show-recovery-code");
            let mut delay = std::time::Duration::from_secs(1);
            loop {
                if let Err(error) = tunnel.run().await {
                    warn!("Tunnel disconnected: {error}");
                }
                loop {
                    tokio::time::sleep(delay).await;
                    match AgentTunnel::connect(&server, local_port, insecure).await {
                        Ok(next) => {
                            tunnel = next;
                            delay = std::time::Duration::from_secs(1);
                            break;
                        }
                        Err(error) => {
                            warn!("Reconnect failed: {error}; retrying");
                            delay = tunnel::next_retry_delay(delay);
                        }
                    }
                }
            }
        }
    }
}

fn local_port_for(game: Option<&str>, port: Option<u16>) -> anyhow::Result<u16> {
    let preset = match game {
        Some(name) => Some(presets::find_preset(name).ok_or_else(|| {
            anyhow::anyhow!("Unknown game '{name}'. Try minecraft, terraria, or --port <PORT>")
        })?),
        None => None,
    };
    if let Some(preset) = preset {
        anyhow::ensure!(
            preset.protocol == Protocol::Tcp,
            "{} requires UDP, which GameNet does not support yet",
            preset.name
        );
    }
    let local_port = port
        .or_else(|| preset.map(|preset| preset.default_port))
        .ok_or_else(|| anyhow::anyhow!("Specify a TCP game or --port <PORT>"))?;
    anyhow::ensure!(local_port != 0, "Local port must be nonzero");
    Ok(local_port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_only_presets_fail_even_with_port_override() {
        assert!(
            local_port_for(Some("bedrock"), None)
                .unwrap_err()
                .to_string()
                .contains("UDP")
        );
        assert!(
            local_port_for(Some("valheim"), Some(2456))
                .unwrap_err()
                .to_string()
                .contains("UDP")
        );
        assert_eq!(local_port_for(Some("minecraft"), None).unwrap(), 25565);
        assert_eq!(local_port_for(None, Some(7777)).unwrap(), 7777);
    }
}
