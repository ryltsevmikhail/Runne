
#[test]
fn direct_deserialization_rejects_oversized_extension() {
    let mut oversized_extension = valid_serialized_call();
    oversized_extension["extension"] = serde_json::json!({"payload": "x".repeat(17_000)});
    assert!(serde_json::from_value::<ProviderCall>(oversized_extension).is_err());
}

#[test]
fn direct_deserialization_rejects_overly_nested_extension() {
    let mut deeply_nested_extension = serde_json::Value::Null;
    for _ in 0..17 {
        deeply_nested_extension = serde_json::json!([deeply_nested_extension]);
    }
    let mut deeply_nested_payload = valid_serialized_call();
    deeply_nested_payload["extension"] = deeply_nested_extension;
    assert!(serde_json::from_value::<ProviderCall>(deeply_nested_payload).is_err());
}

#[test]
fn direct_deserialization_rejects_credential_extension_fields() {
    let mut credential_extension = valid_serialized_call();
    credential_extension["extension"] = serde_json::json!({"api_key": "forbidden"});
    assert!(serde_json::from_value::<ProviderCall>(credential_extension).is_err());
}

#[test]
fn direct_deserialization_rejects_camel_case_credential_extension_fields() {
    for extension in [
        serde_json::json!({"apiKey": "forbidden"}),
        serde_json::json!({"accessToken": "forbidden"}),
        serde_json::json!({"accessToken-": "forbidden"}),
    ] {
        let mut payload = valid_serialized_call();
        payload["extension"] = extension;
        assert!(serde_json::from_value::<ProviderCall>(payload).is_err());
    }
}

#[test]
fn direct_deserialization_rejects_control_characters_in_model_id() {
    let mut payload = valid_serialized_call();
    payload["model_ref"]["model_id"] = serde_json::json!("fixture\nmodel");
    assert!(serde_json::from_value::<ProviderCall>(payload).is_err());
}

#[test]
fn direct_deserialization_rejects_oversized_model_id() {
    let mut payload = valid_serialized_call();
    payload["model_ref"]["model_id"] = serde_json::json!("x".repeat(129));
    assert!(serde_json::from_value::<ProviderCall>(payload).is_err());
}

#[test]
fn direct_deserialization_rejects_invalid_revision() {
    let mut payload = valid_serialized_call();
    payload["model_ref"]["revision"] = serde_json::json!("revision\ninvalid");
    assert!(serde_json::from_value::<ProviderCall>(payload).is_err());
}

#[test]
fn direct_deserialization_rejects_more_than_32_capabilities() {
    let mut excessive_capabilities = valid_serialized_call();
    excessive_capabilities["required_capabilities"] = serde_json::json!(vec!["streaming"; 33]);
    assert!(serde_json::from_value::<ProviderCall>(excessive_capabilities).is_err());
}

#[test]
fn direct_deserialization_preserves_valid_canonical_digest() {
    let call =
        call_with_extension(serde_json::json!({"mode": "safe"})).with_required_capabilities(vec![
            ProviderCapability::Tools,
            ProviderCapability::Streaming,
            ProviderCapability::Tools,
        ]);
    let digest = canonical_provider_call_digest(&call).unwrap();
    let serialized = serde_json::to_vec(&call).unwrap();

    let decoded: ProviderCall = serde_json::from_slice(&serialized).unwrap();

    assert_eq!(serde_json::to_vec(&decoded).unwrap(), serialized);
    assert_eq!(canonical_provider_call_digest(&decoded).unwrap(), digest);
    assert_eq!(
        decoded.required_capabilities(),
        &[ProviderCapability::Streaming, ProviderCapability::Tools]
    );
}

#[test]
fn unknown_finish_reason_preserves_the_bounded_raw_value() {
    let reason = ProviderFinishReason::unknown("future-provider-reason").unwrap();

    assert_eq!(
        reason,
        ProviderFinishReason::Unknown {
            raw: "future-provider-reason".to_owned(),
        }
    );
    assert!(ProviderFinishReason::unknown("x".repeat(129)).is_err());
}

#[test]
fn direct_deserialization_rejects_invalid_unknown_finish_reason() {
    let mut payload =
        serde_json::to_value(ProviderFinishReason::unknown("future").unwrap()).unwrap();
    payload["unknown"]["raw"] = serde_json::json!("future\ninvalid");

    assert!(serde_json::from_value::<ProviderFinishReason>(payload).is_err());
}
