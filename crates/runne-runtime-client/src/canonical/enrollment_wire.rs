#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct EnrollmentResumeWire {
    operation_id: runne_api::ProviderCredentialOperationHandleV2,
}

#[cfg(test)]
mod provider_credential_enrollment_tests {
    use std::time::Duration;

    use serde_json::{Value, json};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::{
        BeginProviderCredentialEnrollment, CanonicalId, CommandIdentity,
        PROVIDER_CREDENTIAL_ENROLLMENT_CAPABILITY_V2, PairProviderCredentialRequest,
        ProviderCredentialEnrollmentActionV2, ProviderCredentialOperationHandleV2,
        ProviderCredentialProviderV2, ProviderCredentialVerificationKindV2, RuntimeApiErrorKind,
        RuntimeSessionInfo, VerifyProviderCredential, mock_authenticated_runtime_client,
        mock_protected_authenticated_runtime_client,
    };
    use runne_api::ProviderCredentialProviderV1;

    #[tokio::test]
    async fn enrollment_requires_exact_protected_capability_before_transport() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let command = begin_command();
        let external = mock_authenticated_runtime_client(
            &origin,
            session(crate::REQUIRED_RUNTIME_CAPABILITIES),
        )
        .unwrap();
        let protected = mock_protected_authenticated_runtime_client(
            &origin,
            session(crate::PROTECTED_RUNTIME_CAPABILITIES),
        )
        .unwrap();

        let legacy = PairProviderCredentialRequest::new(
            CommandIdentity::new(CanonicalId::now_v7(), "legacy-closed").unwrap(),
            ProviderCredentialProviderV1::parse("openai").unwrap(),
            b"not-a-transport-payload".to_vec(),
        )
        .unwrap();
        assert_eq!(
            external
                .pair_provider_credential(legacy)
                .await
                .unwrap_err()
                .kind(),
            RuntimeApiErrorKind::Unavailable,
        );

        for client in [&external, &protected] {
            assert_eq!(
                client
                    .begin_credential_enrollment(command.clone())
                    .await
                    .unwrap_err()
                    .kind(),
                RuntimeApiErrorKind::Incompatible,
            );
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn enrollment_wire_is_metadata_only_and_uses_exact_v2_routes() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let expected = [
                (
                    "POST /v2/provider-credential-enrollment ",
                    "202 Accepted",
                    operation_json("pair", true),
                ),
                (
                    "POST /v2/provider-credential-enrollment/resume ",
                    "200 OK",
                    operation_json("pair", true),
                ),
                (
                    "GET /v2/providers/openai/credential-enrollment ",
                    "200 OK",
                    status_json(),
                ),
                (
                    "POST /v2/provider-credential-enrollment/verify ",
                    "202 Accepted",
                    operation_json("verify_remote", false),
                ),
            ];
            for (request_line, status, response) in expected {
                let (mut stream, _) = listener.accept().await.unwrap();
                let request = read_request(&mut stream).await;
                assert!(
                    request.starts_with(request_line),
                    "unexpected route: {request}"
                );
                if let Some(body) = request
                    .split("\r\n\r\n")
                    .nth(1)
                    .filter(|body| !body.is_empty())
                {
                    assert_safe_json(&serde_json::from_str(body).unwrap());
                }
                let encoded = response.to_string();
                stream.write_all(format!("HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{encoded}", encoded.len()).as_bytes()).await.unwrap();
            }
        });
        let client = mock_protected_authenticated_runtime_client(
            &origin,
            session(crate::ENROLLMENT_QUALIFIED_RUNTIME_CAPABILITIES),
        )
        .unwrap();
        let handle = ProviderCredentialOperationHandleV2::from_bytes([1; 48]).unwrap();

        client
            .begin_credential_enrollment(begin_command())
            .await
            .unwrap();
        assert_eq!(
            client
                .resume_credential_enrollment(handle)
                .await
                .unwrap()
                .operation_handle(),
            handle
        );
        assert_eq!(
            client
                .provider_credential_status(ProviderCredentialProviderV2::OpenAi)
                .await
                .unwrap()
                .provider_id(),
            ProviderCredentialProviderV2::OpenAi
        );
        client
            .verify_provider_credential(verify_command())
            .await
            .unwrap();
        server.await.unwrap();
    }

    fn session(capabilities: &[&str]) -> RuntimeSessionInfo {
        RuntimeSessionInfo {
            profile_id: crate::EXPECTED_BUNDLE_ID.to_owned(),
            schema_hash: crate::GOLDEN_BUNDLE_HASH.to_owned(),
            runtime_version: "test".to_owned(),
            capabilities: capabilities
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
            authority_id: "authority".to_owned(),
            principal_id: "principal".to_owned(),
            event_log_lineage_id: "lineage".to_owned(),
            daemon_instance_id: "daemon".to_owned(),
            launch_generation: 1,
            session_id: "session".to_owned(),
            authorization_epoch: 1,
            sensitivity_ceiling: "sensitive".to_owned(),
            certificate_sha256: "certificate".to_owned(),
            capability_digest: "digest".to_owned(),
        }
    }

    fn begin_command() -> BeginProviderCredentialEnrollment {
        BeginProviderCredentialEnrollment::new(
            ProviderCredentialEnrollmentActionV2::Pair,
            ProviderCredentialProviderV2::OpenAi,
            7,
            "018f0c4e-7b9a-7cc2-8f0a-123456789abc",
            "pair-openai-7",
            "intent-openai-7",
        )
        .unwrap()
    }

    fn verify_command() -> VerifyProviderCredential {
        VerifyProviderCredential::new(
            ProviderCredentialProviderV2::OpenAi,
            7,
            ProviderCredentialVerificationKindV2::Remote,
            "018f0c4e-7b9a-7cc2-8f0a-123456789abc",
            "verify-openai-7",
        )
        .unwrap()
    }

    fn operation_json(kind: &str, broker: bool) -> Value {
        json!({"operationId": "01".repeat(48), "brokerRendezvousId": broker.then_some("rendezvous"), "providerId": "openai", "operationKind": kind, "state": "completed", "lifecycleRevision": 7, "readinessRevision": 7, "cleanupPending": false, "lastDisposition": "completed"})
    }

    fn status_json() -> Value {
        json!({"providerId": "openai", "credentialState": "configured", "readiness": "ready", "lifecycleRevision": 7, "readinessRevision": 7, "observedAt": 1, "verificationState": "not_verified", "verificationRevision": 0, "pendingOperation": null, "cleanupPending": false, "lastDisposition": "completed"})
    }

    async fn read_request(stream: &mut tokio::net::TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut buffer = [0; 1024];
        loop {
            let count = stream.read(&mut buffer).await.unwrap();
            bytes.extend_from_slice(&buffer[..count]);
            if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let headers = std::str::from_utf8(&bytes).unwrap();
        let length = headers
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        let body_start = bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        while bytes.len() - body_start < length {
            let count = stream.read(&mut buffer).await.unwrap();
            bytes.extend_from_slice(&buffer[..count]);
        }
        String::from_utf8(bytes).unwrap()
    }

    fn assert_safe_json(value: &Value) {
        let serialized = value.to_string();
        for forbidden in [
            "credential",
            "ticket",
            "secret",
            "path",
            "releaseDigest",
            "nativeError",
        ] {
            assert!(!serialized.contains(&format!("\"{forbidden}\"")));
        }
        assert!(!serialized.contains(PROVIDER_CREDENTIAL_ENROLLMENT_CAPABILITY_V2));
    }
}
