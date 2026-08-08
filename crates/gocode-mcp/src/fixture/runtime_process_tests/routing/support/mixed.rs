use super::*;
use crate::fixture::process_call::process_permit_digest;
use crate::fixture::runtime::process_ledger::{
    PendingProcessCall, ProcessAdmissionEvidence, ProcessPhaseOutcome, ProcessRefundReason,
    ProcessReservationReceipt, ProcessReserveOutcome,
};
use crate::fixture::{FixtureAuditRecord, FixtureMcpFailure};

pub(in crate::fixture) fn assert_protocol_process_invocation_conflicts() {
    let mut uncertain = mixed_ready(1);
    let mut process = uncertain.issue("mixed-uncertain");
    assert_eq!(
        uncertain.runtime.dispatch(&mut process, None),
        Err(FixtureMcpFailure::DispatchUncertain)
    );
    assert_conflict(&mut uncertain, "mixed-uncertain");

    let mut refunded = mixed_ready(1);
    let receipt = reserve(&refunded, "mixed-refunded");
    refunded
        .runtime
        .refund_process(receipt, ProcessRefundReason::Budget)
        .unwrap();
    assert_conflict(&mut refunded, "mixed-refunded");

    let mut reserved = mixed_ready(1);
    let _ = reserve(&reserved, "mixed-reserved");
    assert_conflict(&mut reserved, "mixed-reserved");

    let mut admitted = mixed_ready(1);
    let _ = admit(&admitted, "mixed-admitted");
    assert_conflict(&mut admitted, "mixed-admitted");

    let mut completed = mixed_ready(1);
    let (receipt, pending) = admit(&completed, "mixed-completed");
    assert!(matches!(
        completed
            .runtime
            .process_ledger_port()
            .settle_completed(receipt, pending),
        ProcessPhaseOutcome::EffectCompleted { .. }
    ));
    assert_conflict(&mut completed, "mixed-completed");
}

fn mixed_ready(limit: u64) -> Ready {
    let raw_authority = authority();
    let host = ProcessContractHostV1::new(
        ProcessClaimJournalMemoryV1::new(),
        ProcessPlatformTargetV1::Linux,
        100,
    );
    let composition = FixtureProcessComposition::new_with_probe(
        raw_authority.clone(),
        host,
        Arc::new(QualifiedProbe),
    );
    let (mut runtime, _, process_authority) = FixtureMcpRuntime::new_with_process_authorities(
        FixtureMcpMode::FixtureOnly,
        identity(),
        vec![process_tool(), protocol_tool()],
        script(),
        &["process", "protocol"],
        FixtureLimits::default(),
        FixtureApprovalPolicy::FixtureDeterministicAllow,
        limit,
        composition,
    )
    .unwrap();
    initialize(&mut runtime, "connection-1", 1);
    let publication = runtime.discover().unwrap();
    Ready {
        runtime,
        authority: process_authority,
        publication,
        raw_authority,
    }
}

fn protocol_tool() -> FixtureTool {
    FixtureTool::new(
        "protocol",
        "1.0.0",
        "fixture",
        serde_json::json!({"type":"object","additionalProperties":false}),
        serde_json::json!({"type":"object","additionalProperties":false}),
    )
    .unwrap()
}

fn reserve(fixture: &Ready, invocation: &str) -> ProcessReservationReceipt {
    let (key, _) = key_payload(fixture, invocation);
    match fixture.runtime.reserve_process(key).unwrap() {
        ProcessReserveOutcome::Owner(receipt) => receipt,
        _ => panic!("expected process reservation owner"),
    }
}

fn admit(fixture: &Ready, invocation: &str) -> (ProcessReservationReceipt, PendingProcessCall) {
    let (key, payload) = key_payload(fixture, invocation);
    let receipt = match fixture.runtime.reserve_process(key).unwrap() {
        ProcessReserveOutcome::Owner(receipt) => receipt,
        _ => panic!("expected process reservation owner"),
    };
    let identity = receipt.identity();
    let (_, request) = payload.mcp().verified_process_call();
    let evidence = ProcessAdmissionEvidence::new(
        request.invocation_id,
        request.request_digest,
        process_permit_digest(
            identity.key_digest(),
            &payload.material().capability().id_label(),
            *payload.material().intent().digest().as_bytes(),
        ),
    );
    let validated = fixture
        .raw_authority
        .bind_call(payload.material().intent().lifecycle_binding())
        .unwrap()
        .validate(
            payload.material().intent().clone(),
            Some(payload.material().capability()),
            Some(payload.material().approval()),
            10,
        )
        .unwrap();
    let mut pending = PendingProcessCall::new(payload, identity.clone(), evidence);
    let ledger = fixture.runtime.process_ledger_port();
    let guard = ledger
        .begin_admission(identity.clone(), pending.admission_evidence())
        .unwrap();
    guard.commit(pending.store_validated(validated, &identity));
    (receipt, pending)
}

fn assert_conflict(fixture: &mut Ready, invocation: &str) {
    let mut protocol = fixture.issue_protocol(invocation);
    let snapshot = snapshot(&fixture.runtime);

    assert_eq!(
        fixture.runtime.dispatch(&mut protocol, None),
        Err(FixtureMcpFailure::InvocationConflict)
    );
    assert_snapshot(&fixture.runtime, snapshot.clone());
    assert_eq!(
        fixture.runtime.dispatch(&mut protocol, None),
        Err(FixtureMcpFailure::InvocationConflict)
    );
    assert_snapshot(&fixture.runtime, snapshot);
}

#[derive(Clone)]
struct Snapshot {
    audit: Vec<FixtureAuditRecord>,
    accounting: u64,
    pending_script: usize,
    dispatches: u64,
    effect_admissions: Option<usize>,
    host_dispatches: Option<usize>,
}

fn snapshot(runtime: &FixtureMcpRuntime) -> Snapshot {
    Snapshot {
        audit: runtime.try_audit().unwrap(),
        accounting: runtime.accounting_remaining(),
        pending_script: runtime.pending_script_steps(),
        dispatches: runtime.dispatch_count(),
        effect_admissions: runtime.process_effect_admission_count_for_test(),
        host_dispatches: runtime.process_host_dispatch_count_for_test(),
    }
}

fn assert_snapshot(runtime: &FixtureMcpRuntime, expected: Snapshot) {
    assert_eq!(runtime.try_audit().unwrap(), expected.audit);
    assert_eq!(runtime.accounting_remaining(), expected.accounting);
    assert_eq!(runtime.pending_script_steps(), expected.pending_script);
    assert_eq!(runtime.dispatch_count(), expected.dispatches);
    assert_eq!(
        runtime.process_effect_admission_count_for_test(),
        expected.effect_admissions
    );
    assert_eq!(
        runtime.process_host_dispatch_count_for_test(),
        expected.host_dispatches
    );
}
