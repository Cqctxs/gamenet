use gamenet_core::protocol::{ControlMessage, Protocol};
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional, BufReader};
use tracing::{info, error};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let server_ip = "127.0.0.1";
    let server_control_addr = format!("{}:5000", server_ip);
    let mut control_stream = TcpStream::connect(&server_control_addr).await?;
    info!("Connected to server: {}", server_control_addr);

    // Register
    let reg = ControlMessage::Register { protocol: Protocol::Tcp, local_port: 25565 };
    control_stream.write_all(&bincode::serialize(&reg)?).await?;

    let mut reader = BufReader::new(control_stream);
    
    //  Performance Tip: Creating the buffer outside the loop!
    // This ensures we reuse the same 1KB of memory for every message we receive.
    let mut buf = [0u8; 1024];

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 { break; } 
        
        let msg: ControlMessage = bincode::deserialize(&buf[..n])?;
        if let ControlMessage::NewConnection { data_port, .. } = msg {
            info!("Player joined! Connecting to server data port: {}", data_port);

            let data_addr = format!("{}:{}", server_ip, data_port);
            let mut server_data_stream = TcpStream::connect(data_addr).await?;
            let mut local_game_stream = TcpStream::connect("127.0.0.1:25565").await?;

            tokio::spawn(async move {
                let _ = copy_bidirectional(&mut server_data_stream, &mut local_game_stream).await;
            });
        }
    }
    Ok(())
}

