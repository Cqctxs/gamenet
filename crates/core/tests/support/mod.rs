use gamenet_core::crypto;
use quinn::{ClientConfig, Connection, ConnectionError, Endpoint, ServerConfig};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use rustls::RootCertStore;
use std::time::Duration;

pub const TEST_TIMEOUT: Duration = Duration::from_secs(5);

/// A fresh local certificate authority and a leaf certificate for localhost.
/// Nothing is installed into the machine's trust store.
pub fn certificates(expired: bool) -> (ServerConfig, RootCertStore) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca = ca_params.self_signed(&ca_key).unwrap();

    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    if expired {
        params.not_before = rcgen::date_time_ymd(2000, 1, 1);
        params.not_after = rcgen::date_time_ymd(2001, 1, 1);
    }
    let cert = params.signed_by(&key, &ca, &ca_key).unwrap();

    let directory = tempfile::tempdir().unwrap();
    let cert_path = directory.path().join("fullchain.pem");
    let key_path = directory.path().join("privkey.pem");
    std::fs::write(&cert_path, format!("{}{}", cert.pem(), ca.pem())).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    let server = crypto::server_config_from_files(&cert_path, &key_path).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    (server, roots)
}

pub struct LocalEndpoints {
    client: Endpoint,
    server: Endpoint,
}

impl LocalEndpoints {
    pub fn new(server_config: ServerConfig, client_config: ClientConfig) -> Self {
        let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(client_config);
        Self { client, server }
    }

    pub async fn connect(
        &self,
        server_name: &str,
    ) -> (
        Result<Connection, ConnectionError>,
        Result<Connection, ConnectionError>,
    ) {
        tokio::time::timeout(TEST_TIMEOUT, async {
            let connecting = self
                .client
                .connect(self.server.local_addr().unwrap(), server_name)
                .unwrap();
            tokio::join!(connecting, async {
                self.server.accept().await.unwrap().await
            })
        })
        .await
        .expect("local TLS handshake timed out")
    }
}

impl Drop for LocalEndpoints {
    fn drop(&mut self) {
        self.client.close(0u32.into(), b"test complete");
        self.server.close(0u32.into(), b"test complete");
    }
}

pub fn assert_certificate_rejection(result: Result<Connection, ConnectionError>, reason: &str) {
    let error = result.unwrap_err();
    match error {
        ConnectionError::TransportError(error) => assert!(
            error.reason.contains(reason),
            "expected certificate rejection containing {reason:?}, got {error}"
        ),
        other => panic!("expected a TLS certificate error, got {other}"),
    }
}
