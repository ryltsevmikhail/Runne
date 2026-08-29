use super::super::request::{
    DaemonLaunchProtocolExpectation, DaemonLaunchRequest, VerifiedDaemonEnrollmentLaunchAuthority,
};
use super::*;
use runne_api::{LaunchSecret, PendingFirstActivationV1, ProtectedLaunchRequestV2};

fn test_enrollment_expectation(
    binding: ProtectedCredentialEnrollmentLaunchBindingV1,
) -> DaemonLaunchProtocolExpectation {
    DaemonLaunchProtocolExpectation::enrollment(VerifiedDaemonEnrollmentLaunchAuthority::test_only(
        ProviderActivationBindingV1::openai_responses_text_v1(),
        binding,
    ))
}

#[test]
fn enrollment_expectation_rejects_legacy_before_key_derivation_and_binds_v3_exactly() {
    let (v1, binding, _) = launch();
    for frame in [
        v1.encode_frame().unwrap(),
        ProtectedLaunchRequestV2::new(
            v1.clone(),
            ProviderActivationBindingV1::openai_responses_text_v1(),
        )
        .unwrap()
        .encode_frame()
        .unwrap(),
    ] {
        let request = DaemonLaunchRequest::decode_frame(&frame).unwrap();
        assert!(
            request
                .validate_for_protocol(
                    15,
                    &validation(&v1),
                    test_enrollment_expectation(binding.clone())
                )
                .is_err()
        );
    }
    let (v3, binding, _) = enrollment_request();
    assert!(
        DaemonLaunchRequest::decode_frame(&v3.encode_frame().unwrap())
            .unwrap()
            .validate_for_protocol(
                15,
                &validation(&v1),
                DaemonLaunchProtocolExpectation::baseline()
            )
            .is_err()
    );
    assert!(
        DaemonLaunchRequest::decode_frame(&v3.encode_frame().unwrap())
            .unwrap()
            .validate_for_protocol(
                15,
                &validation(&v1),
                test_enrollment_expectation(binding.clone())
            )
            .is_ok()
    );
    let v3_accessors = DaemonLaunchRequest::decode_frame(&v3.encode_frame().unwrap()).unwrap();
    assert_eq!(v3_accessors.launch_authority_id(), v1.launch_authority_id());
    assert_eq!(
        v3_accessors.desktop_host_instance_id(),
        v1.desktop_host_instance_id()
    );
    assert_eq!(v3_accessors.runtime_root().to_str(), Some("/tmp/runtime"));
    assert!(matches!(
        v3_accessors.activation_disposition(),
        ActivationDispositionV1::FirstActivation
    ));
    assert!(v3_accessors.validate_freshness(15).is_ok());
    assert!(v3_accessors.validate_freshness(21).is_err());
    let substituted_provider = ProtectedCredentialEnrollmentLaunchRequestV3::new(
        v1.clone(),
        ProviderActivationBindingV1::deepseek_responses_text_v1(),
        binding.clone(),
    )
    .unwrap();
    let substituted_binding = ProtectedCredentialEnrollmentLaunchBindingV1::macos_apple_silicon(
        [20; 32],
        [7; 32],
        [8; 32],
        [9; 32],
        1,
        binding.broker_transfer_commitment().clone(),
    )
    .unwrap();
    let substituted_enrollment = ProtectedCredentialEnrollmentLaunchRequestV3::new(
        v1.clone(),
        ProviderActivationBindingV1::openai_responses_text_v1(),
        substituted_binding,
    )
    .unwrap();
    for request in [substituted_provider, substituted_enrollment] {
        assert!(
            DaemonLaunchRequest::V3(request)
                .validate_for_protocol(
                    15,
                    &validation(&v1),
                    test_enrollment_expectation(binding.clone())
                )
                .is_err()
        );
    }
}

#[test]
fn enrollment_expectation_rejects_copied_binding_under_substituted_secret_or_authority() {
    let (v1, binding, _) = launch();
    let substituted_secret = ProtectedLaunchRequestV1::new(
        v1.launch_authority_id(),
        v1.desktop_host_instance_id(),
        LaunchSecret::from_bytes([30; 32]).unwrap(),
        10,
        20,
        "local-owner",
        profile(),
        v1.executable().clone(),
        "/tmp/runtime".into(),
        ActivationDispositionV1::FirstActivation,
    )
    .unwrap();
    let substituted_authority = ProtectedLaunchRequestV1::new(
        id(31),
        v1.desktop_host_instance_id(),
        LaunchSecret::from_bytes([3; 32]).unwrap(),
        10,
        20,
        "local-owner",
        profile(),
        v1.executable().clone(),
        "/tmp/runtime".into(),
        ActivationDispositionV1::FirstActivation,
    )
    .unwrap();
    for request in [substituted_secret, substituted_authority] {
        let request = ProtectedCredentialEnrollmentLaunchRequestV3::new(
            request,
            ProviderActivationBindingV1::openai_responses_text_v1(),
            binding.clone(),
        )
        .unwrap();
        assert!(
            DaemonLaunchRequest::V3(request)
                .validate_for_protocol(
                    15,
                    &validation(&v1),
                    test_enrollment_expectation(binding.clone())
                )
                .is_err()
        );
    }
}

#[test]
fn v3_first_and_resume_requests_never_panic_through_v1_compatibility() {
    let (first, binding, _) = launch();
    let stable =
        StableRuntimeBindingV1::new(id(40), "local-owner", id(41), "fixture", [1; 32], [2; 32])
            .unwrap();
    let pending = PendingFirstActivationV1::new(
        id(42),
        [43; 32],
        stable,
        first.executable().clone(),
        profile(),
    )
    .unwrap();
    let resumed = ProtectedLaunchRequestV1::new(
        first.launch_authority_id(),
        first.desktop_host_instance_id(),
        LaunchSecret::from_bytes([3; 32]).unwrap(),
        10,
        20,
        "local-owner",
        profile(),
        first.executable().clone(),
        "/tmp/runtime".into(),
        ActivationDispositionV1::ResumeFirstActivation(Box::new(pending)),
    )
    .unwrap();
    for request in [first, resumed] {
        let expected = request.clone();
        let request = DaemonLaunchRequest::V3(
            ProtectedCredentialEnrollmentLaunchRequestV3::new(
                request,
                ProviderActivationBindingV1::openai_responses_text_v1(),
                binding.clone(),
            )
            .unwrap(),
        );
        assert!(request.validate(15, &validation(&expected)).is_err());
        assert!(request.compatibility().is_none());
    }
}
