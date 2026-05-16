use std::path::Path;
use std::sync::Arc;

use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, ServerConfig};
use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;
use rustls::client::danger;
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};

// ── Server-side: self-signed cert (development only) ─────────────────────────

pub fn server_config() -> anyhow::Result<(ServerConfig, CertificateDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    let mut server_config = ServerConfig::with_single_cert(vec![cert_der.clone()], key_der.into())?;
    let transport = Arc::get_mut(&mut server_config.transport).unwrap();
    transport.max_concurrent_bidi_streams(128u8.into());

    Ok((server_config, cert_der))
}

/// Load a TLS certificate chain and private key from PEM files and build a
/// quinn [`ServerConfig`]. Compatible with Let's Encrypt / certbot output
/// (`fullchain.pem` + `privkey.pem`).
pub fn server_config_from_files(cert_path: &Path, key_path: &Path) -> anyhow::Result<ServerConfig> {
    let cert_pem = std::fs::read(cert_path)
        .map_err(|e| anyhow::anyhow!("Cannot read cert {:?}: {}", cert_path, e))?;
    let key_pem = std::fs::read(key_path)
        .map_err(|e| anyhow::anyhow!("Cannot read key {:?}: {}", key_path, e))?;

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow::anyhow!("Failed to parse cert PEM: {}", e))?;

    anyhow::ensure!(!certs.is_empty(), "No certificates found in {:?}", cert_path);

    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .map_err(|e| anyhow::anyhow!("Failed to parse key PEM: {}", e))?
        .ok_or_else(|| anyhow::anyhow!("No private key found in {:?}", key_path))?;

    let mut server_config = ServerConfig::with_single_cert(certs, key)?;
    let transport = Arc::get_mut(&mut server_config.transport).unwrap();
    transport.max_concurrent_bidi_streams(128u8.into());

    Ok(server_config)
}

// ── Client-side: verified TLS against Mozilla CA roots ───────────────────────

/// Build a quinn [`ClientConfig`] that validates the server certificate against
/// Mozilla's bundled CA roots. Works transparently with Let's Encrypt certs.
pub fn client_config() -> anyhow::Result<ClientConfig> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.enable_early_data = true; // preserve QUIC 0-RTT on reconnections
    let quic_crypto = QuicClientConfig::try_from(crypto)?;
    Ok(ClientConfig::new(Arc::new(quic_crypto)))
}

/// Build a quinn [`ClientConfig`] that skips all certificate verification.
///
/// ⚠️  Development only — use only with `--insecure` flag against a local server.
pub fn insecure_client_config() -> anyhow::Result<ClientConfig> {
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();
    crypto.enable_early_data = true;
    let quic_crypto = QuicClientConfig::try_from(crypto)?;
    Ok(ClientConfig::new(Arc::new(quic_crypto)))
}

// ── SkipServerVerification (dev helper) ──────────────────────────────────────

#[derive(Debug)]
struct SkipServerVerification(Arc<CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<danger::ServerCertVerified, rustls::Error> {
        Ok(danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_config_builds_successfully() {
        assert!(client_config().is_ok());
    }

    #[test]
    fn server_config_from_files_loads_valid_pem_cert() {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let dir = std::env::temp_dir();
        let cert_path = dir.join(format!("gamenet-test-cert-{}.pem", ns));
        let key_path = dir.join(format!("gamenet-test-key-{}.pem", ns));

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("rcgen should generate cert");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

        let result = server_config_from_files(&cert_path, &key_path);
        assert!(result.is_ok(), "should load valid cert: {:?}", result.err());

        std::fs::remove_file(&cert_path).ok();
        std::fs::remove_file(&key_path).ok();
    }

    #[test]
    fn server_config_from_files_fails_on_missing_file() {
        let result = server_config_from_files(
            Path::new("/nonexistent/cert.pem"),
            Path::new("/nonexistent/key.pem"),
        );
        assert!(result.is_err());
    }
}
