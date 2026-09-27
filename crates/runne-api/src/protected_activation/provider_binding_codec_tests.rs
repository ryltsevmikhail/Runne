use super::*;

fn base() -> (
    ProtectedLaunchRequestV1,
    ProtectedReadyV1,
    ProtectedActivationKeys,
) {
    let id = super::enrollment_launch_v3_tests::id;
    let profile = ProtectedRuntimeProfileV1::new(
        PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID,
        1,
        "gocode-test/1",
        [1; 32],
        [2; 32],
    )
    .unwrap();
    let request = ProtectedLaunchRequestV1::new(
        id(1),
        id(2),
        LaunchSecret::from_bytes([3; 32]).unwrap(),
        10,
        20,
        "principal",
        profile.clone(),
        ExecutableIdentityV1::new([4; 32], [5; 32], 1).unwrap(),
        PathBuf::from("/tmp/runtime"),
        ActivationDispositionV1::FirstActivation,
    )
    .unwrap();
    let keys = request.derive_keys();
    let stable = StableRuntimeBindingV1::new(
        id(10),
        "principal",
        id(11),
        "gocode-test/1",
        [1; 32],
        [2; 32],
    )
    .unwrap();
    let ready = ProtectedReadyV1::new(
        id(1),
        id(2),
        request.executable().clone(),
        profile,
        stable,
        id(12),
        1,
        id(13),
        "https://127.0.0.1",
        [14; 32],
        vec![15; 32],
        vec!["provider.enroll".into()],
    )
    .unwrap();
    (request, ready, keys)
}

fn deepseek_enrollment_binding(
    keys: &ProtectedActivationKeys,
) -> ProtectedCredentialEnrollmentLaunchBindingV1 {
    let prelude = DaemonEnrollmentLaunchPreludeV1::macos_arm64(
        super::enrollment_launch_v3_tests::id(1),
        super::enrollment_launch_v3_tests::id(2),
        [10; 32],
        [11; 32],
        [12; 32],
        [6; 32],
        [9; 32],
        1,
        10,
        20,
    )
    .unwrap();
    let commitment = CredentialBrokerTransferAuthenticator::from_protected_activation(keys)
        .enrollment_launch_commitment(&prelude);
    ProtectedCredentialEnrollmentLaunchBindingV1::macos_apple_silicon(
        [6; 32], [7; 32], [8; 32], [9; 32], 1, commitment,
    )
    .unwrap()
}

#[test]
fn deepseek_provider_binding_roundtrips_v2_v3_readiness_and_v2_control() {
    let (request, ready, keys) = base();
    let provider = ProviderActivationBindingV1::deepseek_responses_text_v1();

    let mut launch_v2 = ProtectedLaunchRequestV2::new(request.clone(), provider.clone()).unwrap();
    let launch_frame = launch_v2.encode_frame().unwrap();
    launch_v2 = ProtectedLaunchRequestV2::decode_frame(&launch_frame).unwrap();
    assert_eq!(launch_v2.provider_binding(), &provider);

    let mut ready_v2 = ProtectedReadyV2::new(
        ready.clone(),
        provider.clone(),
        ProviderActivationReadinessV1::CredentialMissing,
    )
    .unwrap();
    ready_v2.sign(&keys);
    let ready_v2 = ProtectedReadyV2::decode_frame(&ready_v2.encode_frame().unwrap()).unwrap();
    assert_eq!(ready_v2.provider_binding(), &provider);
    ready_v2.verify_exact(&launch_v2, &keys).unwrap();

    let owned_v1 = ProtectedOwnedLaunchV1::new(
        ready.launch_authority_id,
        ready.desktop_host_instance_id,
        ready.executable().clone(),
        ready.profile().clone(),
        ready.stable().clone(),
        *ready.daemon_instance_id(),
        ready.launch_generation(),
        *ready.session_id(),
    )
    .unwrap();
    let owned_v2 = ProtectedOwnedLaunchV2::new(owned_v1, provider.clone()).unwrap();
    let mut renew = ProtectedRenewRequestV2::new(owned_v2, 1, [21; 32]).unwrap();
    renew.sign(&keys);
    let renew = ProtectedRenewRequestV2::decode_frame(&renew.encode_frame().unwrap()).unwrap();
    assert_eq!(renew.owned_launch().provider_binding(), &provider);
    renew.verify_exact(renew.owned_launch(), 0, &keys).unwrap();

    let enrollment = deepseek_enrollment_binding(&keys);
    let mut launch_v3 = ProtectedCredentialEnrollmentLaunchRequestV3::new(
        request,
        provider.clone(),
        enrollment.clone(),
    )
    .unwrap();
    let launch_frame = launch_v3.encode_frame().unwrap();
    launch_v3 = ProtectedCredentialEnrollmentLaunchRequestV3::decode_frame(&launch_frame).unwrap();
    assert_eq!(launch_v3.provider_binding(), &provider);

    let mut ready_v3 = ProtectedCredentialEnrollmentReadyV3::new(
        ready,
        provider.clone(),
        enrollment,
        ProviderActivationReadinessV1::CredentialMissing,
    )
    .unwrap();
    ready_v3.sign(&launch_v3, &keys).unwrap();
    let ready_v3 =
        ProtectedCredentialEnrollmentReadyV3::decode_frame(&ready_v3.encode_frame().unwrap())
            .unwrap();
    ready_v3.verify_exact(&launch_v3, &keys).unwrap();
    assert_eq!(ready_v3.provider_binding(), &provider);
}

#[test]
fn provider_mode_decoder_rejects_unknown_code() {
    let provider = ProviderActivationBindingV1::deepseek_responses_text_v1();
    let decode_code = |code| {
        let mut encoder = CborEncoder::new();
        encoder.write_map_header(3);
        write_key(&mut encoder, 1);
        encoder.write_unsigned(code);
        write_key(&mut encoder, 2);
        encoder.write_text_string(provider.profile_id());
        write_key(&mut encoder, 3);
        encoder.write_byte_string(provider.profile_digest());
        let bytes = encoder.into_bytes();
        decode_provider_binding(&mut CborDecoder::new(&bytes))
    };
    assert!(matches!(
        decode_code(0),
        Err(DecodeError::UnknownField { key: 0 })
    ));
    assert!(matches!(
        decode_code(12),
        Err(DecodeError::LimitExceeded {
            limit,
            max: 11,
            actual: 12,
        }) if limit == "unsigned"
    ));
    let modes = [
        ProviderActivationModeV1::DeterministicV1,
        ProviderActivationModeV1::OpenAiResponsesTextV1,
        ProviderActivationModeV1::DeepSeekResponsesTextV1,
        ProviderActivationModeV1::LocalEngineTextV1,
        ProviderActivationModeV1::ZaiCodingChatCompletionsTextV1,
        ProviderActivationModeV1::QwenCloudTokenChatCompletionsTextV1,
        ProviderActivationModeV1::GenericChatCompletionsTextV1,
        ProviderActivationModeV1::NativeTextV1,
        ProviderActivationModeV1::RadiusTextV1,
        ProviderActivationModeV1::ResponsesTextV1,
        ProviderActivationModeV1::CloudTextV1,
    ];
    for mode in modes {
        let code = mode.wire_code();
        assert!(code <= ProviderActivationModeV1::MAX_WIRE_CODE);
        assert_eq!(
            ProviderActivationModeV1::from_wire_code(code).unwrap(),
            mode
        );
    }
}

#[test]
fn provider_mode_binding_decode_still_rejects_unknown_profile_data() {
    let mut encoder = CborEncoder::new();
    encoder.write_map_header(3);
    write_key(&mut encoder, 1);
    encoder.write_unsigned(3);
    write_key(&mut encoder, 2);
    encoder.write_text_string("gocode-deepseek-responses-text/1");
    write_key(&mut encoder, 3);
    encoder.write_byte_string(&[0; 32]);
    assert!(decode_provider_binding(&mut CborDecoder::new(&encoder.into_bytes())).is_err());
}
