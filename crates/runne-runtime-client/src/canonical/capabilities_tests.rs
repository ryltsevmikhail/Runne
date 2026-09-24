#[cfg(test)]
mod capabilities_tests {
    use super::*;

    #[test]
    fn v1_credential_control_is_not_advertised_by_any_supported_profile() {
        for profile in [
            REQUIRED_RUNTIME_CAPABILITIES,
            PROTECTED_RUNTIME_CAPABILITIES,
        ] {
            assert!(
                !profile.contains(&"provider.credential-control.v1"),
                "V1 credential control must remain a compatibility artifact only"
            );
        }
    }

    #[test]
    fn enrollment_profile_is_exact_and_supported() {
        for profile in [
            REQUIRED_RUNTIME_CAPABILITIES,
            PROTECTED_RUNTIME_CAPABILITIES,
        ] {
            assert!(
                !profile
                    .iter()
                    .any(|value| value.starts_with("provider.credential-"))
            );
        }
        assert_eq!(
            ENROLLMENT_QUALIFIED_RUNTIME_CAPABILITIES
                .iter()
                .filter(|value| **value == PROVIDER_CREDENTIAL_ENROLLMENT_CAPABILITY_V2)
                .count(),
            1
        );
        assert!(
            !ENROLLMENT_QUALIFIED_RUNTIME_CAPABILITIES.contains(&"provider.credential-control.v1")
        );
        let qualified = ENROLLMENT_QUALIFIED_RUNTIME_CAPABILITIES
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        assert!(is_enrollment_qualified_capability_profile(&qualified));
        assert!(is_supported_capability_profile(&qualified));
        let mut mixed = qualified.clone();
        mixed.swap(0, 1);
        assert!(!is_enrollment_qualified_capability_profile(&mixed));
        mixed = qualified;
        mixed.push("compile-only-qualification".to_owned());
        assert!(!is_enrollment_qualified_capability_profile(&mixed));
    }

    #[test]
    fn protected_profile_match_accepts_only_exact_qualified_capabilities() {
        let qualified = ENROLLMENT_QUALIFIED_RUNTIME_CAPABILITIES
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        assert!(protected_profile_matches(&protected_test_client(qualified)));

        for capabilities in [vec!["arbitrary.capability.v1".to_owned()], {
            let mut values = ENROLLMENT_QUALIFIED_RUNTIME_CAPABILITIES
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>();
            values.push("arbitrary.capability.v1".to_owned());
            values
        }] {
            assert!(!protected_profile_matches(&protected_test_client(
                capabilities
            )));
        }
    }

    #[test]
    fn prompted_submit_profile_check_rejects_profile_two_identity_and_capabilities() {
        let mut session = protected_test_client(
            REQUIRED_RUNTIME_CAPABILITIES
                .iter()
                .map(|value| (*value).to_owned())
                .collect(),
        )
        .session_info()
        .clone();
        assert!(profile3_session_matches(&session));
        session.profile_id = crate::EXPECTED_BUNDLE_ID_V2.to_owned();
        session.schema_hash = crate::GOLDEN_BUNDLE_HASH_V2.to_owned();
        session.capabilities = REQUIRED_RUNTIME_CAPABILITIES_V2
            .iter()
            .map(|value| (*value).to_owned())
            .collect();
        session.capability_digest = capability_digest_hex(&session.capabilities).unwrap();
        assert!(!profile3_session_matches(&session));
    }

    fn protected_test_client(capabilities: Vec<String>) -> AuthenticatedRuntimeClient {
        let capability_digest =
            capability_digest_hex(&capabilities).expect("bounded test capability");
        crate::mock_protected_authenticated_runtime_client(
            "http://127.0.0.1:43123",
            crate::RuntimeSessionInfo {
                profile_id: crate::EXPECTED_BUNDLE_ID.to_owned(),
                schema_hash: crate::GOLDEN_BUNDLE_HASH.to_owned(),
                runtime_version: "test".to_owned(),
                capabilities,
                authority_id: "authority".to_owned(),
                principal_id: "principal".to_owned(),
                event_log_lineage_id: "lineage".to_owned(),
                daemon_instance_id: "daemon".to_owned(),
                launch_generation: 1,
                session_id: "session".to_owned(),
                authorization_epoch: 1,
                sensitivity_ceiling: "sensitive".to_owned(),
                certificate_sha256: "certificate".to_owned(),
                capability_digest,
            },
        )
        .expect("protected test client")
    }
}
