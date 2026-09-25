use super::*;
use tokio::io::duplex;

#[tokio::test]
async fn ready_message_keeps_its_wire_format() {
    let mut bytes = Vec::new();
    send_msg(
        &mut bytes,
        &ControlMessage::TunnelReady { public_port: 10000 },
    )
    .await
    .unwrap();

    // Big-endian frame length, then bincode's little-endian variant and port.
    assert_eq!(bytes, [0, 0, 0, 6, 1, 0, 0, 0, 0x10, 0x27]);
    let mut reader = bytes.as_slice();
    assert!(matches!(
        recv_msg(&mut reader).await.unwrap(),
        Some(ControlMessage::TunnelReady { public_port: 10000 })
    ));
    assert!(recv_msg(&mut reader).await.unwrap().is_none());
}

#[tokio::test]
async fn receives_back_to_back_messages_over_fragmented_reads() {
    let (mut writer, mut reader) = duplex(1);
    let send = async {
        send_msg(
            &mut writer,
            &ControlMessage::TunnelReady { public_port: 12345 },
        )
        .await
        .unwrap();
        send_msg(
            &mut writer,
            &ControlMessage::NewConnection { stream_id: 42 },
        )
        .await
        .unwrap();
        writer.shutdown().await.unwrap();
    };
    let receive = async {
        assert!(matches!(
            recv_msg(&mut reader).await.unwrap(),
            Some(ControlMessage::TunnelReady { public_port: 12345 })
        ));
        assert!(matches!(
            recv_msg(&mut reader).await.unwrap(),
            Some(ControlMessage::NewConnection { stream_id: 42 })
        ));
        assert!(recv_msg(&mut reader).await.unwrap().is_none());
    };

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(send, receive);
    })
    .await
    .expect("fragmented message exchange timed out");
}

#[tokio::test]
async fn clean_end_of_stream_is_not_an_error() {
    assert!(recv_msg(&mut &[][..]).await.unwrap().is_none());
}

#[tokio::test]
async fn rejects_truncated_length_prefix() {
    for length in 1..4 {
        let bytes = [0u8; 3];
        let err = recv_msg(&mut &bytes[..length]).await.unwrap_err();
        assert_eq!(
            err.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }
}

#[tokio::test]
async fn rejects_truncated_payload() {
    let err = recv_msg(&mut &[0, 0, 0, 6, 1, 0, 0, 0][..])
        .await
        .unwrap_err();
    assert_eq!(
        err.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::UnexpectedEof
    );
}

#[tokio::test]
async fn rejects_empty_payload_and_unknown_message_variant() {
    for frame in [&[0, 0, 0, 0][..], &[0, 0, 0, 4, 255, 255, 255, 255][..]] {
        assert!(recv_msg(&mut &frame[..]).await.is_err());
    }
}

#[tokio::test]
async fn rejects_oversized_length_without_waiting_for_payload() {
    let (mut writer, mut reader) = duplex(4);
    writer.write_all(&65_537_u32.to_be_bytes()).await.unwrap();
    // Keep the writer open: rejecting the header must not wait for the body.
    let err = tokio::time::timeout(std::time::Duration::from_secs(5), recv_msg(&mut reader))
        .await
        .expect("oversized frame was not rejected immediately")
        .unwrap_err();
    assert!(err.to_string().contains("too large"));
}

#[tokio::test]
async fn accepts_payload_at_size_limit() {
    // Error = 4-byte variant + 8-byte string length + string contents.
    let message = "x".repeat(65_536 - 12);
    let mut bytes = Vec::new();
    send_msg(
        &mut bytes,
        &ControlMessage::Error {
            message: message.clone(),
        },
    )
    .await
    .unwrap();
    match recv_msg(&mut bytes.as_slice()).await.unwrap() {
        Some(ControlMessage::Error { message: received }) => assert_eq!(received, message),
        other => panic!("expected error message, got {other:?}"),
    }
}
