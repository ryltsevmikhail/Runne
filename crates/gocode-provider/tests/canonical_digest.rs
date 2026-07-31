use gocode_provider::{
    InvalidProviderId, ModelRef, ProviderCall, ProviderCallDigestVersion, ProviderCallId,
    ProviderCapability, ProviderFinishReason, ProviderId, ProviderInputRole, ProviderStreamEvent,
    ProviderTextInput, ProviderUsage, canonical_provider_call_digest,
    canonical_provider_call_digest_for_version, provider_call_wire_bytes_for_version,
};
use sha2::{Digest, Sha256};

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn call_with_extension(extension: serde_json::Value) -> ProviderCall {
    ProviderCall::new(
        ProviderCallId::from_bytes([1; 16]),
        ModelRef::new(
            ProviderId::new("fixture-provider").unwrap(),
            "fixture-model",
            "2026-07-28",
        )
        .unwrap(),
        [2; 32],
        1_024,
        extension,
    )
    .unwrap()
}

fn valid_serialized_call() -> serde_json::Value {
    serde_json::to_value(
        call_with_extension(serde_json::json!({"mode": "safe"}))
            .with_required_capabilities(vec![ProviderCapability::Streaming]),
    )
    .unwrap()
}

#[test]
fn canonical_call_digest_is_order_independent_but_value_sensitive() {
    let left = call_with_extension(serde_json::json!({"a": 1, "b": 2}));
    let reordered = call_with_extension(serde_json::json!({"b": 2, "a": 1}));
    let changed = call_with_extension(serde_json::json!({"a": 1, "b": 3}));

    assert_eq!(
        canonical_provider_call_digest(&left).unwrap(),
        canonical_provider_call_digest(&reordered).unwrap()
    );
    assert_ne!(
        canonical_provider_call_digest(&left).unwrap(),
        canonical_provider_call_digest(&changed).unwrap()
    );
}

#[test]
fn canonical_call_digest_commits_text_input_role_order_and_bytes() {
    let base = call_with_extension(serde_json::json!({"mode": "safe"}));
    let user_then_assistant = base
        .clone()
        .with_text_inputs(vec![
            ProviderTextInput::new(ProviderInputRole::User, "first").unwrap(),
            ProviderTextInput::new(ProviderInputRole::Assistant, "second").unwrap(),
        ])
        .unwrap();
    let assistant_then_user = base
        .clone()
        .with_text_inputs(vec![
            ProviderTextInput::new(ProviderInputRole::Assistant, "second").unwrap(),
            ProviderTextInput::new(ProviderInputRole::User, "first").unwrap(),
        ])
        .unwrap();
    let changed_text = base
        .with_text_inputs(vec![
            ProviderTextInput::new(ProviderInputRole::User, "changed").unwrap(),
            ProviderTextInput::new(ProviderInputRole::Assistant, "second").unwrap(),
        ])
        .unwrap();

    assert_ne!(
        canonical_provider_call_digest(&user_then_assistant).unwrap(),
        canonical_provider_call_digest(&assistant_then_user).unwrap()
    );
    assert_ne!(
        canonical_provider_call_digest(&user_then_assistant).unwrap(),
        canonical_provider_call_digest(&changed_text).unwrap()
    );
}

#[test]
fn provider_call_v1_digest_keeps_the_released_golden_and_v2_is_separate() {
    let legacy_call = call_with_extension(serde_json::json!({"mode": "safe"}))
        .with_required_capabilities(vec![ProviderCapability::Streaming]);
    let v1 =
        canonical_provider_call_digest_for_version(&legacy_call, ProviderCallDigestVersion::V1)
            .unwrap();
    let v2 =
        canonical_provider_call_digest_for_version(&legacy_call, ProviderCallDigestVersion::V2)
            .unwrap();

    assert_eq!(
        v1.as_bytes(),
        &[
            190, 47, 217, 145, 45, 178, 108, 204, 39, 214, 3, 75, 33, 39, 30, 202, 15, 104, 53, 32,
            119, 150, 211, 18, 157, 61, 50, 92, 8, 180, 18, 66,
        ]
    );
    assert_eq!(v1.version(), ProviderCallDigestVersion::V1);
    assert_eq!(v2.version(), ProviderCallDigestVersion::V2);
    assert_ne!(v1.as_bytes(), v2.as_bytes());
}

#[test]
fn provider_call_wire_v1_omits_inputs_and_keeps_its_exact_render_golden() {
    let call = call_with_extension(serde_json::json!({"mode": "safe"}));
    let v1 = provider_call_wire_bytes_for_version(&call, ProviderCallDigestVersion::V1).unwrap();
    let v2 = provider_call_wire_bytes_for_version(&call, ProviderCallDigestVersion::V2).unwrap();

    assert!(!String::from_utf8_lossy(&v1).contains("\"inputs\""));
    assert!(String::from_utf8_lossy(&v2).contains("\"inputs\":[]"));
    assert_eq!(
        lower_hex(&Sha256::digest(&v1)),
        "58450ef9b24e6c54b66d01002c1347c27ac91d5c23a3c1c97b48c9fd9c027c22"
    );
    assert_eq!(
        lower_hex(&Sha256::digest(&v2)),
        "00f54823d1002453d92391bd169f5135001a2e3bf8bb224151885d3d1243b8e7"
    );
}

#[test]
fn provider_call_v1_digest_rejects_v2_text_inputs() {
    let call = call_with_extension(serde_json::Value::Null)
        .with_text_inputs(vec![
            ProviderTextInput::new(ProviderInputRole::User, "new semantics").unwrap(),
        ])
        .unwrap();

    assert!(
        canonical_provider_call_digest_for_version(&call, ProviderCallDigestVersion::V1).is_err()
    );
}

#[test]
fn provider_text_input_rejects_empty_and_more_than_65536_utf8_bytes() {
    assert!(ProviderTextInput::new(ProviderInputRole::User, "").is_err());
    assert!(ProviderTextInput::new(ProviderInputRole::User, "x".repeat(65_536)).is_ok());
    assert!(ProviderTextInput::new(ProviderInputRole::User, "x".repeat(65_537)).is_err());
    assert!(ProviderTextInput::new(ProviderInputRole::User, "я".repeat(32_768)).is_ok());
}

#[test]
fn provider_call_rejects_more_than_64_text_inputs() {
    let inputs = (0..65)
        .map(|index| {
            ProviderTextInput::new(ProviderInputRole::User, format!("input-{index}")).unwrap()
        })
        .collect();

    assert!(
        call_with_extension(serde_json::Value::Null)
            .with_text_inputs(inputs)
            .is_err()
    );
}

#[test]
fn provider_call_rejects_more_than_262144_aggregate_input_bytes() {
    let inputs = (0..5)
        .map(|_| ProviderTextInput::new(ProviderInputRole::User, "x".repeat(65_536)).unwrap())
        .collect();

    assert!(
        call_with_extension(serde_json::Value::Null)
            .with_text_inputs(inputs)
            .is_err()
    );
}

#[test]
fn provider_usage_rejects_inconsistent_details_and_unbounded_totals() {
    assert!(ProviderUsage::new(100, 25, 40, 10).is_ok());
    assert!(ProviderUsage::new(100, 25, 101, 10).is_err());
    assert!(ProviderUsage::new(100, 25, 40, 26).is_err());
    assert!(ProviderUsage::new(1_000_000_000, 0, 0, 0).is_ok());
    assert!(ProviderUsage::new(1_000_000_001, 0, 0, 0).is_err());
    assert!(ProviderUsage::new(u64::MAX, 1, 0, 0).is_err());
}

#[test]
fn normalized_input_usage_and_call_reject_unknown_fields() {
    assert!(
        serde_json::from_value::<ProviderTextInput>(serde_json::json!({
            "role": "user",
            "text": "bounded",
            "credential": "must-not-be-ignored"
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<ProviderUsage>(serde_json::json!({
            "input_tokens": 1,
            "output_tokens": 1,
            "cached_input_tokens": 0,
            "reasoning_output_tokens": 0,
            "future_billing_field": 1
        }))
        .is_err()
    );
    let mut call = valid_serialized_call();
    call["credential"] = serde_json::json!("must-not-be-ignored");
    assert!(serde_json::from_value::<ProviderCall>(call).is_err());

    let mut nested = valid_serialized_call();
    nested["model_ref"]["credential"] = serde_json::json!("must-not-be-ignored");
    assert!(serde_json::from_value::<ProviderCall>(nested).is_err());

    let event = serde_json::json!({
        "sequence": 0,
        "kind": {
            "kind": "started",
            "credential": "must-not-be-ignored"
        }
    });
    assert!(serde_json::from_value::<ProviderStreamEvent>(event).is_err());
}

#[test]
fn provider_id_rejects_empty_overlong_and_control_characters() {
    assert_eq!(ProviderId::new(""), Err(InvalidProviderId::Empty));
    assert_eq!(
        ProviderId::new("x".repeat(129)),
        Err(InvalidProviderId::TooLong {
            max: 128,
            actual: 129,
        })
    );
    assert_eq!(
        ProviderId::new("provider\nname"),
        Err(InvalidProviderId::InvalidCharacter)
    );
}

#[test]
fn provider_call_rejects_zero_output_bound() {
    assert!(
        ProviderCall::new(
            ProviderCallId::from_bytes([1; 16]),
            ModelRef::new(
                ProviderId::new("fixture-provider").unwrap(),
                "fixture-model",
                "2026-07-28",
            )
            .unwrap(),
            [2; 32],
            0,
            serde_json::Value::Null,
        )
        .is_err()
    );
}

#[test]
fn provider_call_bounds_extension_and_rejects_credential_fields() {
    let model_ref = || {
        ModelRef::new(
            ProviderId::new("fixture-provider").unwrap(),
            "fixture-model",
            "2026-07-28",
        )
        .unwrap()
    };
    assert!(
        ProviderCall::new(
            ProviderCallId::from_bytes([1; 16]),
            model_ref(),
            [2; 32],
            1,
            serde_json::json!({"payload": "x".repeat(17_000)}),
        )
        .is_err()
    );
    assert!(
        ProviderCall::new(
            ProviderCallId::from_bytes([1; 16]),
            model_ref(),
            [2; 32],
            1,
            serde_json::json!({"api_key": "forbidden"}),
        )
        .is_err()
    );
}

#[test]
fn direct_deserialization_rejects_zero_output_tokens() {
    let mut zero_tokens = valid_serialized_call();
    zero_tokens["max_output_tokens"] = serde_json::json!(0);
    assert!(serde_json::from_value::<ProviderCall>(zero_tokens).is_err());
}

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
