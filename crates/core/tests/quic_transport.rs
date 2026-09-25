mod support;

use gamenet_core::crypto;
use gamenet_core::message::{recv_msg, send_msg};
use gamenet_core::protocol::{ControlMessage, Protocol};
use support::{LocalEndpoints, TEST_TIMEOUT, assert_certificate_rejection, certificates};

fn conventional_provider() -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    use rustls::crypto::aws_lc_rs;

    std::sync::Arc::new(rustls::crypto::CryptoProvider {
        kx_groups: vec![aws_lc_rs::kx_group::X25519],
        ..aws_lc_rs::default_provider()
    })
}

fn conventional_client(roots: rustls::RootCertStore) -> quinn::ClientConfig {
    use quinn::crypto::rustls::QuicClientConfig;
    use std::sync::Arc;

    let tls = rustls::ClientConfig::builder_with_provider(conventional_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).unwrap()))
}

fn conventional_server() -> (quinn::ServerConfig, rustls::RootCertStore) {
    use quinn::crypto::rustls::QuicServerConfig;
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use std::sync::Arc;

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert);
    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let tls = rustls::ServerConfig::builder_with_provider(conventional_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key.into())
        .unwrap();
    let server =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).unwrap()));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    (server, roots)
}

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

#[tokio::test]
async fn hybrid_relay_rejects_conventional_only_client() {
    let (server, roots) = certificates(false);
    let endpoints = LocalEndpoints::new(server, conventional_client(roots));
    let (client, _) = endpoints.connect("localhost").await;
    assert!(
        client.is_err(),
        "conventional-only client unexpectedly connected"
    );
}

#[tokio::test]
async fn hybrid_client_rejects_conventional_only_relay() {
    let (server, roots) = conventional_server();
    let endpoints = LocalEndpoints::new(server, crypto::client_config_with_roots(roots).unwrap());
    let (client, _) = endpoints.connect("localhost").await;
    assert!(
        client.is_err(),
        "hybrid client used a conventional fallback"
    );
}

#[tokio::test]
async fn development_relay_also_rejects_conventional_only_client() {
    let (server, cert) = crypto::server_config().unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let endpoints = LocalEndpoints::new(server, conventional_client(roots));
    let (client, _) = endpoints.connect("localhost").await;
    assert!(
        client.is_err(),
        "development relay accepted conventional TLS"
    );
}

#[tokio::test]
async fn insecure_development_client_still_requires_hybrid_exchange() {
    let (server, _) = conventional_server();
    let endpoints = LocalEndpoints::new(server, crypto::insecure_client_config().unwrap());
    let (client, _) = endpoints.connect("localhost").await;
    assert!(client.is_err(), "insecure client accepted conventional TLS");
}
