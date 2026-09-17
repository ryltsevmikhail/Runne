
#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::path::PathBuf;

    use super::*;
    use crate::RuntimeEndpoint;
    use runne_api::{
        ActivationDispositionV1, ExecutableIdentityV1, LaunchSecret, ProtectedLaunchRequestV1,
        ProtectedLaunchRequestV2, ProtectedReadyV1, ProtectedReadyV2, ProtectedRuntimeProfileV1,
        ProviderActivationBindingV1, ProviderActivationReadinessV1, StableRuntimeBindingV1,
        ProviderReadinessStatusV1, ProviderStatusSnapshotV1,
    };

    #[test]
    fn local_session_authorization_header_is_sensitive() {
        let marker = URL_SAFE_NO_PAD.encode([0x5a; 32]);
        let credential = RuntimeCredential::from_local_session([0x5a; 32]);
        let header = credential.authorization_header().expect("header");

        assert!(header.is_sensitive());
        assert!(!format!("{header:?}").contains(&marker));
    }

    #[test]
    fn bootstrap_v3_response_decoders_reject_unknown_and_omitted_fields() {
        let challenge = r#"{"wireVersion":"3","keyVersion":1,"challengeId":"AQEBAQEBAQEBAQEBAQEBAQ","serverNonce":"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg","extra":true}"#;
        assert!(serde_json::from_str::<ChallengeResponse>(challenge).is_err());
        let final_response = r#"{"keyVersion":1,"expiresAtMonotonicMillis":1,"sessionId":"018f2e3a700070008000000000000005"}"#;
        assert!(serde_json::from_str::<AuthenticateResponse>(final_response).is_err());
    }

    #[test]
    fn exact_session_tuple_mismatches_are_typed_incompatible() {
        let local = session_peer_fixture();
        let (_, statuses) =
            verify_remote_profile(&local, remote_profile_fixture(&local), [0x22; 16])
                .expect("exact tuple");
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].provider_id(), "openai");

        macro_rules! reject_field {
            ($field:ident, $value:expr) => {{
                let mut remote = remote_profile_fixture(&local);
                remote.$field = $value;
                assert_incompatible(&local, remote, [0x22; 16]);
            }};
        }
        reject_field!(profile_id, "wrong-profile".to_owned());
        reject_field!(schema_hash, "00".repeat(32));
        reject_field!(runtime_version, String::new());
        reject_field!(capabilities, vec!["conversation.create.v1".to_owned()]);
        reject_field!(capability_digest, "00".repeat(32));
        reject_field!(authority_id, "00".repeat(16));
        reject_field!(principal_id, "other-owner".to_owned());
        reject_field!(
            event_log_lineage_id,
            "018f2e3a-7000-7000-8000-000000000004".to_owned()
        );
        reject_field!(
            daemon_instance_id,
            "018f2e3a-7000-7000-8000-000000000005".to_owned()
        );
        reject_field!(launch_generation, 8);
        reject_field!(session_id, "44".repeat(16));
        reject_field!(authorization_epoch, 1);
        reject_field!(sensitivity_ceiling, "internal".to_owned());
        reject_field!(certificate_sha256, "55".repeat(32));
        assert_incompatible(&local, remote_profile_fixture(&local), [0x44; 16]);
    }

    #[test]
    fn protected_profile_is_path_free_and_rejects_external_transport_downgrade() {
        let (request, ready, keys) =
            protected_ready_fixture(PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID);
        let profile = ProtectedBundledRuntimeProfile::from_ready(&ready, &request, &keys)
            .expect("exact protected profile");
        assert_eq!(profile.peer.executable_sha256, [0x11; 32]);
        assert_eq!(profile.peer.launch_authority_id, request.launch_authority_id());
        let debug = format!("{profile:?}");
        assert!(debug.contains(PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID));
        assert!(!debug.contains("bootstrap"));
        assert!(!debug.contains("secret"));

        let (external_request, external_ready, external_keys) =
            protected_ready_fixture("gocode-local-runtime/2");
        assert_eq!(
            ProtectedBundledRuntimeProfile::from_ready(
                &external_ready,
                &external_request,
                &external_keys,
            )
            .expect_err("credential-first profile is never bundled"),
            LaunchAuthorityError::DowngradedExternalProfile
        );
    }

    #[test]
    fn provider_bound_v2_profile_requires_the_exact_outer_readiness_proof() {
        let (request_v1, ready_v1, keys) =
            protected_ready_fixture(PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID);
        let binding = ProviderActivationBindingV1::openai_responses_text_v1();
        let request = ProtectedLaunchRequestV2::new(request_v1, binding.clone()).unwrap();
        let mut ready = ProtectedReadyV2::new(ready_v1, binding, ProviderActivationReadinessV1::Ready).unwrap();
        ready.sign(&keys);

        ProtectedBundledRuntimeProfile::from_ready_v2(&ready, &request, &keys)
            .expect("exact V2 protected profile");

        let changed = ProviderActivationBindingV1::deterministic_v1();
        let changed_request =
            ProtectedLaunchRequestV2::new(request.compatibility_request().clone(), changed)
                .unwrap();
        assert_eq!(
            ProtectedBundledRuntimeProfile::from_ready_v2(&ready, &changed_request, &keys)
                .expect_err("provider profile change must fail closed"),
            LaunchAuthorityError::ProviderModeMismatch
        );
    }

    fn session_peer_fixture() -> SessionPeer {
        let schema_hash: [u8; 32] = hex::decode(GOLDEN_BUNDLE_HASH)
            .expect("schema digest")
            .try_into()
            .expect("32 byte schema digest");
        let authority_id = [0x11; 16];
        let event_log_lineage_id =
            uuid::Uuid::parse_str("018f2e3a-7000-7000-8000-000000000003").expect("lineage UUID");
        let daemon_instance_id =
            uuid::Uuid::parse_str("018f2e3a-7000-7000-8000-000000000002").expect("daemon UUID");
        let capabilities = crate::PROTECTED_RUNTIME_CAPABILITIES
            .iter()
            .map(|capability| (*capability).to_owned())
            .collect::<Vec<_>>();
        let capability_digest = [0x22; 32];
        let certificate_sha256 = [0x33; 32];
        SessionPeer {
        expected_authorization_epoch: 0,
            endpoint: RuntimeEndpoint::loopback(SocketAddr::from((Ipv4Addr::LOCALHOST, 8443)))
                .expect("loopback"),
            origin: "https://127.0.0.1:8443".to_owned(),
            certificate_der: vec![1],
            certificate_sha256,
            executable_sha256: [0x0e; 32],
            launch_authority_id: [0x12; 16],
            authority_id,
            principal_id: "local-owner".to_owned(),
            event_log_lineage_id,
            daemon_instance_id,
            launch_generation: 7,
            expected_session_id: None,
            schema_hash,
            capabilities,
            capability_digest,
            provider_binding: None,
        }
    }

    fn remote_profile_fixture(local: &SessionPeer) -> SessionRuntimeProfileWire {
        SessionRuntimeProfileWire {
            profile_id: crate::EXPECTED_BUNDLE_ID.to_owned(),
            schema_hash: GOLDEN_BUNDLE_HASH.to_owned(),
            runtime_version: "0.0.1".to_owned(),
            capabilities: local.capabilities.clone(),
            capability_digest: hex::encode(local.capability_digest),
            authority_id: hex::encode(local.authority_id),
            principal_id: "local-owner".to_owned(),
            event_log_lineage_id: local.event_log_lineage_id.to_string(),
            daemon_instance_id: local.daemon_instance_id.to_string(),
            launch_generation: 7,
            session_id: "22222222222222222222222222222222".to_owned(),
            authorization_epoch: 0,
            sensitivity_ceiling: "sensitive".to_owned(),
            certificate_sha256: hex::encode(local.certificate_sha256),
            provider_statuses: vec![ProviderStatusSnapshotV1::new(
                "openai",
                "openai_responses_text_v1",
                "openai-responses-text-v1",
                [0x11; 32],
                ProviderReadinessStatusV1::Ready,
                true,
            )
            .expect("provider status")],
        }
    }

    fn assert_incompatible(
        local: &SessionPeer,
        remote: SessionRuntimeProfileWire,
        issued_session_id: [u8; 16],
    ) {
        let error = verify_remote_profile(local, remote, issued_session_id)
            .expect_err("tuple mismatch must be rejected");
        assert!(matches!(
            error,
            LocalRuntimeConnectError::Api(ref api)
                if api.kind() == RuntimeApiErrorKind::Incompatible
        ));
    }

    fn protected_ready_fixture(
        transport_profile_id: &str,
    ) -> (
        ProtectedLaunchRequestV1,
        ProtectedReadyV1,
        ProtectedActivationKeys,
    ) {
        let authority = uuid_bytes(1);
        let host = uuid_bytes(2);
        let lineage = uuid_bytes(3);
        let instance = uuid_bytes(4);
        let session = uuid_bytes(5);
        let executable =
            ExecutableIdentityV1::new([0x11; 32], [0x12; 32], 4_096).expect("executable");
        let schema_hash: [u8; 32] = hex::decode(GOLDEN_BUNDLE_HASH)
            .expect("schema hash")
            .try_into()
            .expect("32 byte schema hash");
        let capabilities = crate::PROTECTED_RUNTIME_CAPABILITIES
            .iter()
            .map(|capability| (*capability).to_owned())
            .collect::<Vec<_>>();
        let capability_digest = ordered_capability_digest(&capabilities);
        let runtime_profile = ProtectedRuntimeProfileV1::new(
            transport_profile_id,
            1,
            crate::EXPECTED_BUNDLE_ID,
            schema_hash,
            capability_digest,
        )
        .expect("runtime profile");
        let stable = StableRuntimeBindingV1::new(
            authority,
            "local-owner",
            lineage,
            crate::EXPECTED_BUNDLE_ID,
            schema_hash,
            capability_digest,
        )
        .expect("stable binding");
        let secret = LaunchSecret::from_bytes([0xa5; 32]).expect("launch secret");
        let keys = secret.derive_keys();
        let request = ProtectedLaunchRequestV1::new(
            authority,
            host,
            secret,
            1_000,
            31_000,
            "local-owner",
            runtime_profile.clone(),
            executable.clone(),
            protected_runtime_root(),
            ActivationDispositionV1::FirstActivation,
        )
        .expect("launch");
        let certificate_der = vec![1, 2, 3, 4];
        let certificate_sha256 = Sha256::digest(&certificate_der).into();
        let mut ready = ProtectedReadyV1::new(
            authority,
            host,
            executable,
            runtime_profile,
            stable,
            instance,
            7,
            session,
            "https://127.0.0.1:43123",
            certificate_sha256,
            certificate_der,
            capabilities,
        )
        .expect("ready");
        ready.sign(&keys);
        (request, ready, keys)
    }

    fn uuid_bytes(last: u8) -> [u8; 16] {
        [
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0x00, 0, 0, 0, 0, 0, last,
        ]
    }

    fn protected_runtime_root() -> PathBuf {
        #[cfg(unix)]
        {
            PathBuf::from("/private/tmp/runne-protected-runtime")
        }
        #[cfg(not(unix))]
        {
            PathBuf::from(r"C:\runne-protected-runtime")
        }
    }
}
