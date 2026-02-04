use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:7878").await?;
    
    loop {
        let (stream, addr) = listener.accept().await?;
        println!("New connection from {addr}");
        
        // Spawn a task for each connection (like threads, but lighter)
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream).await {
                eprintln!("Error: {e}");
            }
        });
    }
}

async fn handle_connection(mut stream: TcpStream) -> anyhow::Result<()> {
    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await?;
    
    let response = b"HTTP/1.1 200 OK\r\n\r\nHello from async!";
    stream.write_all(response).await?;
    
    Ok(())
}