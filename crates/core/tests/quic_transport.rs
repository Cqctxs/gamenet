mod support;

use gamenet_core::crypto;
use gamenet_core::message::{recv_msg, send_msg};
use gamenet_core::protocol::{ControlMessage, Protocol};
use support::{LocalEndpoints, TEST_TIMEOUT, assert_certificate_rejection, certificates};

#[tokio::test]
async fn control_messages_round_trip_over_verified_quic() {
    let (server_config, roots) = certificates(false);
    let endpoints = LocalEndpoints::new(
        server_config,
        crypto::client_config_with_roots(roots).unwrap(),
    );
    let (client, server) = endpoints.connect("localhost").await;
    let (client, server) = (client.unwrap(), server.unwrap());

    let agent = async {
        let (mut send, mut recv) = client.open_bi().await.unwrap();
        send_msg(
            &mut send,
            &ControlMessage::Register {
                protocol: Protocol::Tcp,
                local_port: 25565,
                token: [42; 32],
            },
        )
        .await
        .unwrap();
        send.finish().unwrap();
        assert!(matches!(
            recv_msg(&mut recv).await.unwrap(),
            Some(ControlMessage::TunnelReady { public_port: 10000 })
        ));
        assert!(recv_msg(&mut recv).await.unwrap().is_none());
    };
    let relay = async {
        let (mut send, mut recv) = server.accept_bi().await.unwrap();
        match recv_msg(&mut recv).await.unwrap() {
            Some(ControlMessage::Register {
                protocol,
                local_port,
                token,
            }) => {
                assert_eq!(protocol, Protocol::Tcp);
                assert_eq!(local_port, 25565);
                assert_eq!(token, [42; 32]);
            }
            other => panic!("expected registration, got {other:?}"),
        }
        assert!(recv_msg(&mut recv).await.unwrap().is_none());
        send_msg(
            &mut send,
            &ControlMessage::TunnelReady { public_port: 10000 },
        )
        .await
        .unwrap();
        send.finish().unwrap();
    };
    tokio::time::timeout(TEST_TIMEOUT, async {
        tokio::join!(agent, relay);
    })
    .await
    .expect("control-message exchange timed out");
}

#[tokio::test]
async fn default_client_rejects_an_untrusted_certificate() {
    let (server, _) = certificates(false);
    let endpoints = LocalEndpoints::new(server, crypto::client_config().unwrap());
    let (client, _) = endpoints.connect("localhost").await;
    assert_certificate_rejection(client, "UnknownIssuer");
}

#[tokio::test]
async fn trusted_certificate_for_a_different_host_is_rejected() {
    let (server, roots) = certificates(false);
    let endpoints = LocalEndpoints::new(server, crypto::client_config_with_roots(roots).unwrap());
    let (client, _) = endpoints.connect("wrong-host.example").await;
    assert_certificate_rejection(client, "not valid for name");
}

#[tokio::test]
async fn expired_certificate_from_a_trusted_issuer_is_rejected() {
    let (server, roots) = certificates(true);
    let endpoints = LocalEndpoints::new(server, crypto::client_config_with_roots(roots).unwrap());
    let (client, _) = endpoints.connect("localhost").await;
    assert_certificate_rejection(client, "expired");
}
