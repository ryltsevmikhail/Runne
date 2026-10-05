use runne_provider::{
    ModelRef, ProviderCall, ProviderCallDigestVersion, ProviderCallId, ProviderCapability,
    ProviderId, ProviderInputRole, ProviderTextInput, ProviderToolDeclarationV1,
    ProviderToolNameV1, ProviderToolResultV1, canonical_provider_call_digest,
    provider_call_wire_bytes_for_version,
};

fn call() -> ProviderCall {
    ProviderCall::new(
        ProviderCallId::from_bytes([5; 16]),
        ModelRef::new(ProviderId::new("openai").unwrap(), "gpt-5.5", "2026-04-23").unwrap(),
        [7; 32],
        128,
        serde_json::json!({"profile_id":"test"}),
    )
    .unwrap()
    .with_text_inputs(vec![
        ProviderTextInput::new(ProviderInputRole::User, "read file").unwrap(),
    ])
    .unwrap()
}

fn tool_call(output: &str, call_id: &str) -> ProviderCall {
    let result = ProviderToolResultV1::new(
        call_id.to_owned(),
        ProviderToolNameV1::WorkspaceFileRead,
        r#"{"path":"notes.txt"}"#.to_owned(),
        output.to_owned(),
    )
    .unwrap();
    call()
        .with_tool_context(
            vec![ProviderToolDeclarationV1::for_name(
                ProviderToolNameV1::WorkspaceFileRead,
            )],
            vec![result],
        )
        .unwrap()
        .with_required_capabilities(vec![
            ProviderCapability::Streaming,
            ProviderCapability::Tools,
        ])
}

#[test]
fn tool_schema_and_correlated_result_are_roundtripped_and_digest_bound() {
    let first = tool_call(r#"{"content":"hello"}"#, "call_A");
    let changed_result = tool_call(r#"{"content":"changed"}"#, "call_A");
    let changed_identity = tool_call(r#"{"content":"hello"}"#, "call_B");
    let digest = canonical_provider_call_digest(&first).unwrap();
    assert_ne!(
        digest,
        canonical_provider_call_digest(&changed_result).unwrap()
    );
    assert_ne!(
        digest,
        canonical_provider_call_digest(&changed_identity).unwrap()
    );
    let bytes =
        provider_call_wire_bytes_for_version(&first, ProviderCallDigestVersion::V2).unwrap();
    let restored: ProviderCall = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(first, restored);
    assert_eq!(digest, canonical_provider_call_digest(&restored).unwrap());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["tool_declarations"][0]["parameters"],
        ProviderToolNameV1::WorkspaceFileRead.parameters()
    );
}

#[test]
fn malformed_or_unbounded_tool_context_is_rejected() {
    let malformed = serde_json::json!({
        "name":"workspace.file.read",
        "parameters":{"type":"object","properties":{},"required":[],"additionalProperties":true}
    });
    assert!(serde_json::from_value::<ProviderToolDeclarationV1>(malformed).is_err());
    assert!(
        ProviderToolResultV1::new(
            "call_A".to_owned(),
            ProviderToolNameV1::WorkspaceFileRead,
            "x".repeat(8 * 1024 + 1),
            String::new(),
        )
        .is_err()
    );
    assert!(
        call()
            .with_tool_context(
                vec![],
                vec![
                    ProviderToolResultV1::new(
                        "call_A".to_owned(),
                        ProviderToolNameV1::WorkspaceFileRead,
                        "{}".to_owned(),
                        "ok".to_owned(),
                    )
                    .unwrap()
                ],
            )
            .is_err()
    );
}
