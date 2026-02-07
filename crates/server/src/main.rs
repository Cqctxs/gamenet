use gamenet_core::protocol::{ControlMessage, Protocol};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tracing::{info, error};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let control_listener = TcpListener::bind("0.0.0.0:5000").await?;
    info!("Server: Control port 5000 open.");

    loop {
        let (mut control_stream, addr) = control_listener.accept().await?;
        info!("Agent connected: {}", addr);
        tokio::spawn(async move {
            if let Err(e) = handle_agent(&mut control_stream).await {
                error!("Agent error: {}", e);
            }
        });
    }
}

async fn handle_agent(control_stream: &mut TcpStream) -> anyhow::Result<()> {
    let mut buf = [0u8; 1024];
    let n = control_stream.read(&mut buf).await?;
    let msg: ControlMessage = bincode::deserialize(&buf[..n])?;

    if let ControlMessage::Register { local_port, .. } = msg {
         info!("Registration received: Tunneling local port {}", local_port);

         let player_listener = TcpListener::bind("0.0.0.0:25565").await?;
         info!("Server: Player port 25565 is now OPEN.");

         loop {
             let (mut player_stream, player_addr) = player_listener.accept().await?;
             info!("Player connected: {}", player_addr);

             // 1. Ask the OS for a random free port for this specific player
             let data_listener = TcpListener::bind("0.0.0.0:0").await?;
             let assigned_port = data_listener.local_addr()?.port();

             // 2. Signal the Agent and tell it which port to connect to
             let signal = ControlMessage::NewConnection { 
                 stream_id: 0, 
                 data_port: assigned_port 
             };
             let data = bincode::serialize(&signal)?;
             control_stream.write_all(&data).await?;

             // 3. Wait for the Agent to connect to that assigned port
             let (mut agent_data_stream, _) = data_listener.accept().await?;

             tokio::spawn(async move {
                 if let Err(e) = copy_bidirectional(&mut player_stream, &mut agent_data_stream).await {
                     error!("Bridge closed: {}", e);
                 }
             });
         }
    }
    
    Ok(())
}

