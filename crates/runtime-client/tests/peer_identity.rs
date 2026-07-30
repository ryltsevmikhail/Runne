#![cfg(unix)]

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use gocode_runtime_client::{
    EXPECTED_BUNDLE_ID, GOLDEN_BUNDLE_HASH, LocalRuntimeConnectError, LocalRuntimeProfile,
};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;

const CAPABILITIES: &[&str] = &[
    "conversation.create.v1",
    "conversation.generate_text.v1",
    "conversation.list_messages.v1",
];

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

    let bootstrap_path = directory.path().join("bootstrap.secret");
    fs::write(&bootstrap_path, b"must-not-be-read").expect("bootstrap marker");
    secure(&bootstrap_path);
    let profile_path = directory.path().join("client-profile.json");
    let certificate_sha256 = hex::encode(Sha256::digest(&profile_certificate));
    let capability_digest = ordered_capability_digest(CAPABILITIES);
    fs::write(
        &profile_path,
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "transportProfileId": "gocode-local-runtime/2",
            "profileId": EXPECTED_BUNDLE_ID,
            "schemaHash": GOLDEN_BUNDLE_HASH,
            "capabilities": CAPABILITIES,
            "capabilityDigest": hex::encode(capability_digest),
            "endpoint": format!("https://{endpoint}"),
            "certificateDerBase64": STANDARD.encode(&profile_certificate),
            "certificateSha256": certificate_sha256,
            "bootstrapSecretPath": bootstrap_path,
            "authorityId": "018f2e3a700070008000000000000001",
            "principalId": "local-owner",
            "eventLogLineageId": "018f2e3a-7000-7000-8000-000000000003",
            "daemonInstanceId": "018f2e3a-7000-7000-8000-000000000002",
            "launchGeneration": 7
        }))
        .expect("profile JSON"),
    )
    .expect("write profile");
    secure(&profile_path);

    let profile = LocalRuntimeProfile::load(&profile_path).expect("load v2 profile");
    let Err(error) = profile.connect(Duration::from_secs(2)).await else {
        panic!("counterfeit certificate must fail before HTTP");
    };

    assert_eq!(
        error,
        LocalRuntimeConnectError::Transport(
            gocode_runtime_client::RuntimeTransportError::PeerIdentityMismatch
        )
    );
    assert_eq!(accepted_tls.load(Ordering::SeqCst), 0);
    assert_eq!(
        fs::read(&bootstrap_path).expect("bootstrap marker remains"),
        b"must-not-be-read"
    );
}

fn tls_identity() -> (Vec<u8>, Arc<rustls::ServerConfig>) {
    let mut parameters = CertificateParams::new(Vec::new()).expect("certificate parameters");
    parameters.subject_alt_names = vec![SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))];
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
