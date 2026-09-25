use std::sync::Arc as SharedArc;

use runne_api::ProviderCredentialProviderV2;
use runne_runtime_client::{
    ENROLLMENT_QUALIFIED_RUNTIME_CAPABILITIES, GOLDEN_BUNDLE_HASH, RuntimeSessionInfo,
    mock_protected_authenticated_runtime_client,
};
use tokio::io::{AsyncReadExt as EnrollmentAsyncReadExt, AsyncWriteExt as EnrollmentAsyncWriteExt};

#[tokio::test]
async fn enrollment_status_refresh_returns_only_the_exact_safe_projection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 1024];
        let length = EnrollmentAsyncReadExt::read(&mut stream, &mut request)
            .await
            .unwrap();
        assert!(std::str::from_utf8(&request[..length])
            .unwrap()
            .starts_with("GET /v2/providers/openai/credential-enrollment HTTP/1.1"));
        let body = r#"{"providerId":"openai","credentialState":"configured","readiness":"ready","lifecycleRevision":7,"readinessRevision":8,"observedAt":9,"verificationState":"local_verified","verificationRevision":7,"pendingOperation":null,"cleanupPending":false,"lastDisposition":"completed"}"#;
        EnrollmentAsyncWriteExt::write_all(
            &mut stream,
            format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    });
    let directory = tempfile::tempdir().unwrap();
    let core = AppCore::open_bundled_anchored(
        &directory.path().join("profile.sqlite3"),
        SharedArc::new(runne_secure_store::test_support::DeterministicSecureStore::new([7; 32])),
        [7; 32],
    )
    .unwrap();
    let lease = core.begin_bundled_runtime_start().await.unwrap();
    core.install_bundled_runtime_client(lease, enrollment_client(&origin))
        .await
        .unwrap();

    let projection = core
        .provider_credential_enrollment_status(ProviderCredentialProviderV2::OpenAi)
        .await
        .unwrap();
    let value = serde_json::to_value(projection).unwrap();
    assert_eq!(value["providerId"], "openai");
    assert_eq!(value["verificationState"], "local_verified");
    assert_eq!(value.as_object().unwrap().len(), 11);
    for prohibited in ["credential", "ticket", "secret", "nativePath", "releaseDigest"] {
        assert!(value.get(prohibited).is_none());
    }
    server.await.unwrap();
}

fn enrollment_client(origin: &str) -> runne_runtime_client::AuthenticatedRuntimeClient {
    let capabilities = ENROLLMENT_QUALIFIED_RUNTIME_CAPABILITIES
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    mock_protected_authenticated_runtime_client(
        origin,
        RuntimeSessionInfo {
            profile_id: runne_runtime_client::EXPECTED_BUNDLE_ID.into(),
            schema_hash: GOLDEN_BUNDLE_HASH.into(),
            runtime_version: "test".into(),
            capability_digest: capability_digest(&capabilities),
            capabilities,
            authority_id: "authority".into(),
            principal_id: "principal".into(),
            event_log_lineage_id: "lineage".into(),
            daemon_instance_id: "daemon".into(),
            launch_generation: 1,
            session_id: "session".into(),
            authorization_epoch: 1,
            sensitivity_ceiling: "sensitive".into(),
            certificate_sha256: "11".repeat(32),
        },
    )
    .unwrap()
}

fn capability_digest(capabilities: &[String]) -> String {
    use sha2::Digest as _;

    let mut digest = sha2::Sha256::new();
    digest.update(b"gocode/local-runtime/capability-digest/v1\0");
    digest.update(u32::try_from(capabilities.len()).unwrap().to_be_bytes());
    for capability in capabilities {
        digest.update(u32::try_from(capability.len()).unwrap().to_be_bytes());
        digest.update(capability.as_bytes());
    }
    hex::encode(digest.finalize())
}
