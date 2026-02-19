use std::sync::Arc;

use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, ServerConfig};
use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;
use rustls::client::danger;
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};

// ---------------------------------------------------------------------------
// Server-side: generate a self-signed cert and return a quinn ServerConfig
// ---------------------------------------------------------------------------

/// Generate a self-signed TLS certificate and build a QUIC server config.
///
/// Returns `(ServerConfig, cert_der)` — the cert bytes are needed by the
/// client when using `client_config_trusted()`.
pub fn server_config() -> anyhow::Result<(ServerConfig, CertificateDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

    let mut server_config = ServerConfig::with_single_cert(vec![cert_der.clone()], key_der.into())?;

    let transport = Arc::get_mut(&mut server_config.transport).unwrap();
    transport.max_concurrent_bidi_streams(128u8.into());

    Ok((server_config, cert_der))
}

// ---------------------------------------------------------------------------
// Client-side: skip certificate verification (dev / self-signed only!)
// ---------------------------------------------------------------------------

/// Build a quinn [`ClientConfig`] that **skips all certificate verification**.
///
/// ⚠️  This is for development only!  In production you should pin or trust
/// the server certificate.
pub fn insecure_client_config() -> anyhow::Result<ClientConfig> {
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();

    // Enable 0-RTT early data so reconnections skip the handshake
    crypto.enable_early_data = true;

    let quic_crypto = QuicClientConfig::try_from(crypto)?;
    Ok(ClientConfig::new(Arc::new(quic_crypto)))
}

// ---------------------------------------------------------------------------
// SkipServerVerification — taken from the quinn docs
// ---------------------------------------------------------------------------

/// Implementation of `ServerCertVerifier` that verifies everything as trustworthy.
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
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<danger::HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
