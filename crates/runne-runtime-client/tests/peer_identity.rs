#![cfg(unix)]

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rcgen::{
    BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    PKCS_ECDSA_P256_SHA256, SanType,
};
use runne_runtime_client::{
    EXPECTED_BUNDLE_ID, GOLDEN_BUNDLE_HASH, LocalRuntimeConnectError, LocalRuntimeProfile,
    REQUIRED_RUNTIME_CAPABILITIES,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;

#[tokio::test]
async fn counterfeit_listener_receives_no_http_or_bootstrap_material() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (profile_certificate, _) = tls_identity();
    let (_, counterfeit_config) = tls_identity();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("counterfeit listener");
    let endpoint = listener.local_addr().expect("listener address");
    let accepted_tls = Arc::new(AtomicUsize::new(0));
    let accepted_tls_task = Arc::clone(&accepted_tls);
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept TCP");
        if tokio_rustls::TlsAcceptor::from(counterfeit_config)
            .accept(stream)
            .await
            .is_ok()
        {
            accepted_tls_task.fetch_add(1, Ordering::SeqCst);
        }
    });

    let (profile_path, bootstrap_path) =
        write_profile(directory.path(), endpoint, &profile_certificate);

    let profile = LocalRuntimeProfile::load(&profile_path).expect("load v2 profile");
    let Err(error) = profile.connect(Duration::from_secs(2)).await else {
        panic!("counterfeit certificate must fail before HTTP");
    };

    assert_eq!(
        error,
        LocalRuntimeConnectError::Transport(
            runne_runtime_client::RuntimeTransportError::PeerIdentityMismatch
        )
    );
    assert_eq!(accepted_tls.load(Ordering::SeqCst), 0);
    assert_eq!(
        fs::read(&bootstrap_path).expect("bootstrap marker remains"),
        b"must-not-be-read"
    );
}

#[tokio::test]
async fn pinned_certificate_with_wrong_san_reaches_no_http_or_bootstrap_material() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (certificate, server_config) =
        tls_identity_with_san(SanType::DnsName("localhost".try_into().expect("DNS name")));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("listener");
    let endpoint = listener.local_addr().expect("listener address");
    let accepted_tls = Arc::new(AtomicUsize::new(0));
    let accepted_tls_task = Arc::clone(&accepted_tls);
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept TCP");
        if tokio_rustls::TlsAcceptor::from(server_config)
            .accept(stream)
            .await
            .is_ok()
        {
            accepted_tls_task.fetch_add(1, Ordering::SeqCst);
        }
    });
    let (profile_path, bootstrap_path) = write_profile(directory.path(), endpoint, &certificate);

    let result = LocalRuntimeProfile::load(&profile_path)
        .expect("load profile")
        .connect(Duration::from_secs(2))
        .await;
    let Err(error) = result else {
        panic!("IP endpoint must reject a DNS-only SAN");
    };
    assert_eq!(
        error,
        LocalRuntimeConnectError::Transport(
            runne_runtime_client::RuntimeTransportError::PeerIdentityMismatch
        )
    );
    assert_eq!(accepted_tls.load(Ordering::SeqCst), 0);
    assert_eq!(fs::read(bootstrap_path).unwrap(), b"must-not-be-read");
}

#[tokio::test]
async fn ca_signed_counterfeit_reaches_no_http_or_bootstrap_material() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let (profile_certificate, _) = tls_identity();
    let counterfeit_config = ca_signed_tls_identity();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("listener");
    let endpoint = listener.local_addr().expect("listener address");
    let accepted_tls = Arc::new(AtomicUsize::new(0));
    let accepted_tls_task = Arc::clone(&accepted_tls);
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept TCP");
        if tokio_rustls::TlsAcceptor::from(counterfeit_config)
            .accept(stream)
            .await
            .is_ok()
        {
            accepted_tls_task.fetch_add(1, Ordering::SeqCst);
        }
    });
    let (profile_path, bootstrap_path) =
        write_profile(directory.path(), endpoint, &profile_certificate);

    let result = LocalRuntimeProfile::load(&profile_path)
        .expect("load profile")
        .connect(Duration::from_secs(2))
        .await;
    let Err(error) = result else {
        panic!("CA-signed listener must not replace the exact pinned leaf");
    };
    assert_eq!(
        error,
        LocalRuntimeConnectError::Transport(
            runne_runtime_client::RuntimeTransportError::PeerIdentityMismatch
        )
    );
    assert_eq!(accepted_tls.load(Ordering::SeqCst), 0);
    assert_eq!(fs::read(bootstrap_path).unwrap(), b"must-not-be-read");
}

fn tls_identity() -> (Vec<u8>, Arc<rustls::ServerConfig>) {
    tls_identity_with_san(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)))
}

fn tls_identity_with_san(san: SanType) -> (Vec<u8>, Arc<rustls::ServerConfig>) {
    let mut parameters = CertificateParams::new(Vec::new()).expect("certificate parameters");
    parameters.subject_alt_names = vec![san];
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
    let certificate = parameters.self_signed(&key).expect("certificate");
    let certificate_der = certificate.der().to_vec();
    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .expect("TLS versions")
    .with_no_client_auth()
    .with_single_cert(
        vec![CertificateDer::from(certificate_der.clone())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
    )
    .expect("server config");
    (certificate_der, Arc::new(server_config))
}

fn ca_signed_tls_identity() -> Arc<rustls::ServerConfig> {
    let mut ca_parameters = CertificateParams::new(Vec::new()).expect("CA parameters");
    ca_parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_parameters.key_usages.push(KeyUsagePurpose::KeyCertSign);
    let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("CA key");
    let ca_certificate = ca_parameters.self_signed(&ca_key).expect("CA certificate");
    let issuer = Issuer::new(ca_parameters, ca_key);

    let mut leaf_parameters = CertificateParams::new(Vec::new()).expect("leaf parameters");
    leaf_parameters.subject_alt_names = vec![SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))];
    let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let leaf_certificate = leaf_parameters
        .signed_by(&leaf_key, &issuer)
        .expect("CA-signed leaf");
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("TLS versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![
                CertificateDer::from(leaf_certificate.der().to_vec()),
                CertificateDer::from(ca_certificate.der().to_vec()),
            ],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .expect("server config"),
    )
}

fn write_profile(
    directory: &std::path::Path,
    endpoint: std::net::SocketAddr,
    certificate: &[u8],
) -> (std::path::PathBuf, std::path::PathBuf) {
    let bootstrap_path = directory.join("bootstrap.secret");
    fs::write(&bootstrap_path, b"must-not-be-read").expect("bootstrap marker");
    secure(&bootstrap_path);
    let profile_path = directory.join("client-profile.json");
    let certificate_sha256 = hex::encode(Sha256::digest(certificate));
    let capability_digest = ordered_capability_digest(REQUIRED_RUNTIME_CAPABILITIES);
    fs::write(
        &profile_path,
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 3,
            "transportProfileId": "runne-local-runtime/2",
            "profileId": EXPECTED_BUNDLE_ID,
            "schemaHash": GOLDEN_BUNDLE_HASH,
            "capabilities": REQUIRED_RUNTIME_CAPABILITIES,
            "capabilityDigest": hex::encode(capability_digest),
            "endpoint": format!("https://{endpoint}"),
            "certificateDerBase64": STANDARD.encode(certificate),
            "certificateSha256": certificate_sha256,
            "executableSha256": "0e".repeat(32),
            "bootstrapSecretPath": bootstrap_path,
            "launchAuthorityId": "018f2e3a700070008000000000000006",
            "authorityId": "018f2e3a700070008000000000000001",
            "principalId": "local-owner",
            "eventLogLineageId": "018f2e3a-7000-7000-8000-000000000003",
            "daemonInstanceId": "018f2e3a-7000-7000-8000-000000000002",
            "launchGeneration": 7,
            "sessionId": "018f2e3a700070008000000000000005"
        }))
        .expect("profile JSON"),
    )
    .expect("write profile");
    secure(&profile_path);
    (profile_path, bootstrap_path)
}

fn ordered_capability_digest(capabilities: &[&str]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"gocode/local-runtime/capability-digest/v1\0");
    hasher.update(u32::try_from(capabilities.len()).unwrap().to_be_bytes());
    for capability in capabilities {
        hasher.update(u32::try_from(capability.len()).unwrap().to_be_bytes());
        hasher.update(capability.as_bytes());
    }
    hasher.finalize().into()
}

fn secure(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("secure file");
}
