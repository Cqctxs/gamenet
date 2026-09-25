use crate::protocol::ControlMessage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_CONTROL_MSG_BYTES: usize = 64 * 1024;

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

pub async fn recv_msg<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> anyhow::Result<Option<ControlMessage>> {
    let mut len_buf = [0u8; 4];
    // EOF is clean only between frames, not partway through a length prefix.
    if reader.read(&mut len_buf[..1]).await? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut len_buf[1..]).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_CONTROL_MSG_BYTES {
        return Err(anyhow::anyhow!(
            "Control message too large: {} bytes (max {})",
            len,
            MAX_CONTROL_MSG_BYTES
        ));
    }
    let mut data = vec![0u8; len];
    reader.read_exact(&mut data).await?;
    Ok(Some(bincode::deserialize(&data)?))
}

#[cfg(test)]
mod tests;
