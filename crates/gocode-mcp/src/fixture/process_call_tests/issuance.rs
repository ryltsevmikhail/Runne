use super::support::*;
use std::panic::{AssertUnwindSafe, catch_unwind};

#[test]
fn typed_issuance_creates_a_consumable_payload_without_runtime_effects() {
    let mut runtime = runtime();
    initialize(&mut runtime);
    let publication = runtime.discover().unwrap();
    let (authority, intent) = authority_and_intent(&publication.binding, "invocation-1");
    let before = (
        runtime.accounting_remaining(),
        runtime.dispatch_count(),
        runtime.process_gateway_present(),
    );
    let intent_digest = intent.digest();

    let mut capability = publication
        .issue_process_dispatch_for_test(
            "process",
            "invocation-1",
            json!({}),
            intent,
            &authority,
            20,
            10,
        )
        .unwrap();

    assert_eq!(
        capability.execution_class(),
        crate::McpToolExecutionClass::ProcessBacked
    );
    assert!(capability.process_key().is_some());
    assert_eq!(
        before,
        (
            runtime.accounting_remaining(),
            runtime.dispatch_count(),
            runtime.process_gateway_present()
        )
    );
    let key = capability.process_key().unwrap().digest();
    let payload = capability.take_process_payload().unwrap();
    assert_eq!(
        payload.mcp().execution_class(),
        crate::McpToolExecutionClass::ProcessBacked
    );
    assert_eq!(payload.material().issued_at(), 10);
    assert_eq!(payload.material().intent().digest(), intent_digest);
    assert_eq!(capability.process_key().unwrap().digest(), key);
    assert_eq!(
        capability.execution_class(),
        crate::McpToolExecutionClass::ProcessBacked
    );
    assert!(!format!("{capability:?}").contains("tool"));
    capability.restore_process_payload(payload);
    assert!(capability.take_process_payload().is_some());
}

#[test]
fn typed_issuance_rejects_schema_and_secret_input_before_payload_creation() {
    let mut runtime = runtime();
    initialize(&mut runtime);
    let publication = runtime.discover().unwrap();
    let (authority, intent) = authority_and_intent(&publication.binding, "invocation-1");

    assert!(matches!(
        publication.issue_process_dispatch_for_test(
            "process",
            "invocation-1",
            json!({"extra":true}),
            intent.clone(),
            &authority,
            20,
            10
        ),
        Err(FixtureMcpFailure::InputSchemaMismatch)
    ));
    assert!(matches!(
        publication.issue_process_dispatch_for_test(
            "process",
            "invocation-1",
            json!({"secret":"sentinel"}),
            intent,
            &authority,
            20,
            10
        ),
        Err(FixtureMcpFailure::SecretMaterialRejected)
    ));
    assert_eq!(runtime.accounting_remaining(), 1);
    assert_eq!(runtime.dispatch_count(), 0);
}

#[test]
fn typed_issuance_rejects_mismatched_intent_before_process_authorization() {
    let mut runtime = runtime();
    initialize(&mut runtime);
    let publication = runtime.discover().unwrap();
    let (authority, _) = authority_and_intent(&publication.binding, "invocation-1");
    let (_, intent) = authority_and_intent(&publication.binding, "invocation-2");
    let before = (
        runtime.accounting_remaining(),
        runtime.dispatch_count(),
        runtime.process_gateway_present(),
    );

    assert!(matches!(
        publication.issue_process_dispatch_for_test(
            "process",
            "invocation-1",
            json!({}),
            intent.clone(),
            &authority,
            20,
            10
        ),
        Err(FixtureMcpFailure::ProcessCapabilityInvalid)
    ));
    let capability = authority.issue_capability(&intent, 20).unwrap();

    assert_eq!(&capability.id_label()[8..], &1u64.to_be_bytes());
    assert_eq!(
        before,
        (
            runtime.accounting_remaining(),
            runtime.dispatch_count(),
            runtime.process_gateway_present()
        )
    );
}

#[test]
fn ordinary_and_typed_issuance_remain_class_fail_closed() {
    let mut runtime = runtime();
    initialize(&mut runtime);
    let publication = runtime.discover().unwrap();
    let (authority, intent) = authority_and_intent(&publication.binding, "invocation-1");

    assert!(matches!(
        publication.issue_dispatch(
            "process",
            "invocation-1",
            json!({}),
            "principal",
            "authority",
            20
        ),
        Err(FixtureMcpFailure::ProcessIntentRequired)
    ));
    let protocol_tool = FixtureTool::new(
        "protocol",
        "1.0.0",
        "fixture",
        json!({"type":"object","additionalProperties":false}),
        json!({"type":"object","additionalProperties":false}),
    )
    .unwrap();
    let mut protocol_runtime = FixtureMcpRuntime::new(
        FixtureMcpMode::FixtureOnly,
        FixtureIdentity::new(
            McpServerId::new("protocol-server").unwrap(),
            "1.0.0",
            "fixture-v1",
            "2025-11-25",
        )
        .unwrap(),
        vec![protocol_tool],
        FixtureScript::new(vec![FixtureStep::response_at(0, json!({})).unwrap()]).unwrap(),
        &["protocol"],
        FixtureLimits::default(),
        FixtureApprovalPolicy::FixtureDeterministicAllow,
        1,
    )
    .unwrap();
    protocol_runtime
        .initialize(FixtureInitialize::new(
            McpRuntimeInstanceId::new("runtime-1").unwrap(),
            McpSessionId::new("session-1").unwrap(),
            McpConnectionId::new("connection-1").unwrap(),
            1,
            "protocol-server",
            "1.0.0",
            "fixture-v1",
            "2025-11-25",
        ))
        .unwrap();
    let protocol_publication = protocol_runtime.discover().unwrap();
    assert!(matches!(
        protocol_publication.issue_process_dispatch_for_test(
            "protocol",
            "invocation-1",
            json!({}),
            intent,
            &authority,
            20,
            10
        ),
        Err(FixtureMcpFailure::ExecutionClassMismatch)
    ));
}

#[test]
fn restoring_an_occupied_process_payload_fails_fast() {
    let mut runtime = runtime();
    initialize(&mut runtime);
    let publication = runtime.discover().unwrap();
    let (authority, first_intent) = authority_and_intent(&publication.binding, "invocation-1");
    let (_, second_intent) = authority_and_intent(&publication.binding, "invocation-2");
    let mut first = publication
        .issue_process_dispatch_for_test(
            "process",
            "invocation-1",
            json!({}),
            first_intent,
            &authority,
            20,
            10,
        )
        .unwrap();
    let mut second = publication
        .issue_process_dispatch_for_test(
            "process",
            "invocation-2",
            json!({}),
            second_intent,
            &authority,
            20,
            10,
        )
        .unwrap();
    let first_payload = first.take_process_payload().unwrap();
    let second_payload = second.take_process_payload().unwrap();

    first.restore_process_payload(first_payload);
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            first.restore_process_payload(second_payload);
        }))
        .is_err()
    );
}
