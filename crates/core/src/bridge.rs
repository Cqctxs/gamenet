use std::io;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, copy};

/// Copy both directions of a split TCP/QUIC bridge, preserving half-closes.
pub async fn copy_halves<TR, TW, QR, QW>(
    mut tcp_read: TR,
    mut tcp_write: TW,
    mut quic_read: QR,
    mut quic_write: QW,
) -> io::Result<()>
where
    TR: AsyncRead + Unpin,
    TW: AsyncWrite + Unpin,
    QR: AsyncRead + Unpin,
    QW: AsyncWrite + Unpin,
{
    let to_quic = async {
        copy(&mut tcp_read, &mut quic_write).await?;
        quic_write.shutdown().await
    };
    let to_tcp = async {
        copy(&mut quic_read, &mut tcp_write).await?;
        tcp_write.shutdown().await
    };
    tokio::try_join!(to_quic, to_tcp)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn half_closed_request_still_receives_full_response() {
        let (bridge_tcp, mut player) = tokio::io::duplex(1024);
        let (bridge_quic, mut agent) = tokio::io::duplex(1024);
        let (tcp_read, tcp_write) = tokio::io::split(bridge_tcp);
        let (quic_read, quic_write) = tokio::io::split(bridge_quic);
        let bridge = tokio::spawn(copy_halves(tcp_read, tcp_write, quic_read, quic_write));

        player.write_all(b"request").await.unwrap();
        player.shutdown().await.unwrap();
        let mut request = Vec::new();
        agent.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request");
        assert!(
            !bridge.is_finished(),
            "the response direction must remain live"
        );
        agent.write_all(b"response").await.unwrap();
        agent.shutdown().await.unwrap();
        let mut response = Vec::new();
        player.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"response");
        bridge.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn half_closed_response_still_accepts_remaining_request() {
        let (bridge_tcp, mut player) = tokio::io::duplex(1024);
        let (bridge_quic, mut agent) = tokio::io::duplex(1024);
        let (tcp_read, tcp_write) = tokio::io::split(bridge_tcp);
        let (quic_read, quic_write) = tokio::io::split(bridge_quic);
        let bridge = tokio::spawn(copy_halves(tcp_read, tcp_write, quic_read, quic_write));

        agent.write_all(b"response").await.unwrap();
        agent.shutdown().await.unwrap();
        let mut response = Vec::new();
        player.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"response");
        assert!(
            !bridge.is_finished(),
            "the request direction must remain live"
        );
        player.write_all(b"request").await.unwrap();
        player.shutdown().await.unwrap();
        let mut request = Vec::new();
        agent.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request");
        bridge.await.unwrap().unwrap();
    }
}
