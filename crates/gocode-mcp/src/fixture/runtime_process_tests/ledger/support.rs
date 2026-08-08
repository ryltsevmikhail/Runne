use super::super::super::{
    FixtureApprovalPolicy, FixtureIdentity, FixtureInitialize, FixtureLimits, FixtureMcpMode,
    FixtureMcpRuntime, FixtureScript, FixtureStep, FixtureTool,
};
use super::super::super::{
    process_call::{ProcessDispatchPayload, ProcessEffectKey, process_permit_digest},
    runtime::process_ledger::*,
};
use super::material::authority_and_intent;
use crate::{McpConnectionId, McpRuntimeInstanceId, McpServerId, McpSessionId};

pub(super) fn runtime(limit: u64) -> FixtureMcpRuntime {
    FixtureMcpRuntime::new(
        FixtureMcpMode::FixtureOnly,
        FixtureIdentity::new(
            McpServerId::new("fixture-server").unwrap(),
            "1.0.0",
            "fixture-v1",
            "2025-11-25",
        )
        .unwrap(),
        vec![
            FixtureTool::new_process_backed(
                "process",
                "1.0.0",
                "fixture",
                serde_json::json!({"type":"object","additionalProperties":false}),
                serde_json::json!({"type":"object","additionalProperties":false}),
            )
            .unwrap(),
        ],
        FixtureScript::new(vec![
            FixtureStep::response_at(0, serde_json::json!({})).unwrap(),
        ])
        .unwrap(),
        &["process"],
        FixtureLimits::default(),
        FixtureApprovalPolicy::FixtureDeterministicAllow,
        limit,
    )
    .unwrap()
}

pub(super) fn key() -> ProcessEffectKey {
    key_with(0)
}

pub(super) fn key_with(field: usize) -> ProcessEffectKey {
    let mut issuer = [1; 32];
    let mut definition = [2; 32];
    let mut approval = [3; 32];
    let mut request = [4; 32];
    let mut binding = [5; 32];
    let mut intent = [6; 32];
    let mut invocation = "raw-invocation-sentinel".to_owned();
    let mut connection = "raw-connection-sentinel".to_owned();
    let mut generation = 1;
    let mut tool = "process".to_owned();
    match field {
        1 => issuer = [9; 32],
        2 => definition = [9; 32],
        3 => approval = [9; 32],
        4 => invocation = "invocation-2".to_owned(),
        5 => request = [9; 32],
        6 => binding = [9; 32],
        7 => connection = "connection-2".to_owned(),
        8 => generation = 2,
        9 => tool = "other".to_owned(),
        10 => intent = [9; 32],
        _ => {}
    }
    ProcessEffectKey::new(
        issuer, definition, approval, invocation, request, binding, connection, generation, tool,
        intent,
    )
}

pub(super) fn owner(
    runtime: &FixtureMcpRuntime,
    key: ProcessEffectKey,
) -> ProcessReservationReceipt {
    match runtime.reserve_process(key).unwrap() {
        ProcessReserveOutcome::Owner(receipt) => receipt,
        _ => panic!("expected Owner"),
    }
}

pub(super) fn poison_after_admission(runtime: &FixtureMcpRuntime) {
    let receipt = owner(runtime, key());
    let identity = receipt.identity();
    let (pending, _) = pending_and_validated(identity.clone());
    let port = runtime.process_ledger_port();
    let guard = port
        .begin_admission(identity, pending.admission_evidence())
        .unwrap();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = guard;
        panic!("deterministic retained-guard fault");
    }));
}

pub(super) fn admit(
    runtime: &FixtureMcpRuntime,
) -> (
    ProcessEffectKey,
    ProcessReservationReceipt,
    PendingProcessCall,
) {
    let (key, receipt, mut pending, validated) = reserved_pending(runtime);
    let identity = receipt.identity();
    let port = runtime.process_ledger_port();
    let guard = port
        .begin_admission(identity.clone(), pending.admission_evidence())
        .unwrap();
    let token = pending.store_validated(validated, &identity);
    guard.commit(token);
    (key, receipt, pending)
}

pub(super) fn reserved_pending(
    runtime: &FixtureMcpRuntime,
) -> (
    ProcessEffectKey,
    ProcessReservationReceipt,
    PendingProcessCall,
    gocode_tools::ValidatedProcessIntentV1,
) {
    let (key, payload, validated) = process_payload_and_validated();
    let receipt = owner(runtime, key.clone());
    let identity = receipt.identity();
    let evidence = admission_evidence(&identity, &payload);
    (
        key,
        receipt,
        PendingProcessCall::new(payload, identity, evidence),
        validated,
    )
}

pub(super) fn pending_and_validated(
    identity: ProcessReceiptIdentity,
) -> (PendingProcessCall, gocode_tools::ValidatedProcessIntentV1) {
    pending_and_validated_with_evidence_override(identity, None)
}

pub(super) fn pending_and_validated_with_evidence_override(
    identity: ProcessReceiptIdentity,
    evidence_override: Option<ProcessAdmissionEvidence>,
) -> (PendingProcessCall, gocode_tools::ValidatedProcessIntentV1) {
    let (_, payload, validated) = process_payload_and_validated();
    let evidence = evidence_override.unwrap_or_else(|| admission_evidence(&identity, &payload));
    (
        PendingProcessCall::new(payload, identity, evidence),
        validated,
    )
}

fn process_payload_and_validated() -> (
    ProcessEffectKey,
    ProcessDispatchPayload,
    gocode_tools::ValidatedProcessIntentV1,
) {
    let mut setup = runtime(1);
    setup
        .initialize(FixtureInitialize::new(
            McpRuntimeInstanceId::new("runtime-1").unwrap(),
            McpSessionId::new("session-1").unwrap(),
            McpConnectionId::new("raw-connection-sentinel").unwrap(),
            1,
            "fixture-server",
            "1.0.0",
            "fixture-v1",
            "2025-11-25",
        ))
        .unwrap();
    let publication = setup.discover().unwrap();
    let (authority, raw_authority, intent) =
        authority_and_intent(&publication.binding, "raw-invocation-sentinel");
    let mut capability = publication
        .issue_process_dispatch_for_test(
            "process",
            "raw-invocation-sentinel",
            serde_json::json!({}),
            intent,
            &authority,
            20,
            10,
        )
        .unwrap();
    let key = capability.process_key().cloned().unwrap();
    let payload = capability.take_process_payload().unwrap();
    let lifecycle_binding = payload.material().intent().lifecycle_binding();
    let validated = raw_authority
        .bind_call(lifecycle_binding)
        .unwrap()
        .validate(
            payload.material().intent().clone(),
            Some(payload.material().capability()),
            Some(payload.material().approval()),
            10,
        )
        .unwrap();
    (key, payload, validated)
}

fn admission_evidence(
    identity: &ProcessReceiptIdentity,
    payload: &ProcessDispatchPayload,
) -> ProcessAdmissionEvidence {
    let (_, request) = payload.mcp().verified_process_call();
    ProcessAdmissionEvidence::new(
        request.invocation_id,
        request.request_digest,
        process_permit_digest(
            identity.key_digest(),
            &payload.material().capability().id_label(),
            *payload.material().intent().digest().as_bytes(),
        ),
    )
}
