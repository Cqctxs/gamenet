use crate::protocol::ControlMessage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Send a ControlMessage with a 4-byte length prefix.
///
/// Wire format: [4 bytes: payload length as big-endian u32][N bytes: bincode payload]
pub async fn send_msg<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &ControlMessage,
) -> anyhow::Result<()> {
    let payload = bincode::serialize(msg)?;
    let len = (payload.len() as u32).to_be_bytes();
    writer.write_all(&len).await?;
    writer.write_all(&payload).await?;
    Ok(())
}

/// Receive a length-prefixed ControlMessage.
/// Returns `None` if the connection was closed cleanly.
pub async fn recv_msg<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> anyhow::Result<Option<ControlMessage>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut data = vec![0u8; len];
    reader.read_exact(&mut data).await?;
    Ok(Some(bincode::deserialize(&data)?))
}
