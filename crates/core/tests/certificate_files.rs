use gamenet_core::crypto::server_config_from_files;

fn load_certificate_files(cert: &str, key: &str) -> anyhow::Result<quinn::ServerConfig> {
    let directory = tempfile::tempdir()?;
    let cert_path = directory.path().join("cert.pem");
    let key_path = directory.path().join("key.pem");
    std::fs::write(&cert_path, cert)?;
    std::fs::write(&key_path, key)?;
    server_config_from_files(&cert_path, &key_path)
}

#[test]
fn empty_certificate_file_is_rejected() {
    let key = rcgen::KeyPair::generate().unwrap();
    assert!(load_certificate_files("", &key.serialize_pem()).is_err());
}

#[test]
fn malformed_certificate_pem_is_rejected() {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = "-----BEGIN CERTIFICATE-----\n!invalid!\n-----END CERTIFICATE-----\n";
    assert!(load_certificate_files(cert, &key.serialize_pem()).is_err());
}

#[test]
fn empty_private_key_file_is_rejected() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    assert!(load_certificate_files(&cert.cert.pem(), "").is_err());
}

#[test]
fn malformed_private_key_pem_is_rejected() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = "-----BEGIN PRIVATE KEY-----\n!invalid!\n-----END PRIVATE KEY-----\n";
    assert!(load_certificate_files(&cert.cert.pem(), key).is_err());
}

#[test]
fn private_key_for_a_different_certificate_is_rejected() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let unrelated_key = rcgen::KeyPair::generate().unwrap();
    assert!(load_certificate_files(&cert.cert.pem(), &unrelated_key.serialize_pem()).is_err());
}
