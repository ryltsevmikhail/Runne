use runne_provider::{
    CanonicalProviderError, ModelRef, ProviderCall, ProviderCallDigestVersion, ProviderCallId,
    ProviderId, ProviderInputRole, ProviderTextInput, canonical_provider_call_digest_for_version,
};

fn call() -> ProviderCall {
    ProviderCall::new(
        ProviderCallId::from_bytes([7; 16]),
        ModelRef::new(ProviderId::new("openai").unwrap(), "gpt-test", "v1").unwrap(),
        [9; 32],
        1,
        serde_json::json!({}),
    )
    .unwrap()
}

fn call_with_text_input() -> ProviderCall {
    call()
        .with_text_inputs(vec![
            ProviderTextInput::new(ProviderInputRole::User, "hello").unwrap(),
        ])
        .unwrap()
}

#[test]
fn v1_deterministic_compatibility_without_text_inputs_is_accepted_with_v1_digest() {
    let digest = canonical_provider_call_digest_for_version(&call(), ProviderCallDigestVersion::V1)
        .expect("V1 deterministic call");

    assert_eq!(digest.version(), ProviderCallDigestVersion::V1);
}

#[test]
fn v1_with_text_inputs_is_rejected_for_production_semantics() {
    assert!(matches!(
        canonical_provider_call_digest_for_version(
            &call_with_text_input(),
            ProviderCallDigestVersion::V1,
        ),
        Err(CanonicalProviderError::V1TextInputs)
    ));
}

#[test]
fn v2_with_text_inputs_is_accepted() {
    let digest = canonical_provider_call_digest_for_version(
        &call_with_text_input(),
        ProviderCallDigestVersion::V2,
    )
    .expect("V2 text inputs");

    assert_eq!(digest.version(), ProviderCallDigestVersion::V2);
}
