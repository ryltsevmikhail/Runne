use std::panic::{AssertUnwindSafe, catch_unwind};

use super::super::super::runtime::process_ledger::ProcessPhaseOutcome;
use super::super::super::{
    FixtureAuditProcessPhase, FixtureCallResult, FixtureMcpFailure, FixtureTool,
};
use super::support::*;

#[test]
fn try_audit_reports_poison() {
    let runtime = runtime(1);
    poison_after_admission(&runtime);
    assert_eq!(
        runtime.try_audit(),
        Err(FixtureMcpFailure::InvalidStateTransition)
    );
}

#[test]
fn legacy_audit_panics_when_state_is_unavailable() {
    let runtime = runtime(1);
    poison_after_admission(&runtime);
    assert!(catch_unwind(AssertUnwindSafe(|| runtime.audit())).is_err());
}

#[test]
fn audit_stores_only_canonical_metadata() {
    let runtime = runtime(1);
    let (key, receipt, pending) = admit(&runtime);
    assert!(matches!(
        runtime
            .process_ledger_port()
            .settle_completed(receipt, pending),
        ProcessPhaseOutcome::EffectCompleted { .. }
    ));
    let audit = runtime.audit();
    let fields = key.audit_fields();
    assert_eq!(
        audit
            .iter()
            .map(|record| record.process_phase())
            .collect::<Vec<_>>(),
        [
            Some(FixtureAuditProcessPhase::Reserved),
            Some(FixtureAuditProcessPhase::Admitted),
            Some(FixtureAuditProcessPhase::Completed),
        ]
    );
    let completed = audit.last().unwrap();
    assert_eq!(completed.result(), Some(FixtureCallResult::Completed));
    assert_eq!(completed.request_digest(), fields.request_digest());
    assert_eq!(completed.binding_digest(), fields.binding_digest());
    assert_eq!(completed.intent_digest(), Some(fields.intent_digest()));
    assert_eq!(
        completed.connection_digest(),
        super::super::super::process_call::audit_connection_digest(key.connection_id())
    );
    assert_eq!(completed.generation(), fields.generation());
    assert_eq!(completed.tool_digest(), fields.tool_digest());
}

#[test]
fn audit_debug_is_sentinel_only() {
    let runtime = runtime(1);
    let (_, receipt, pending) = admit(&runtime);
    let _ = runtime
        .process_ledger_port()
        .settle_completed(receipt, pending);
    let debug = format!("{:?}", runtime.audit().last().unwrap());
    assert_eq!(debug, "FixtureAuditRecord { fixture_only: true }");
    for raw in [
        "raw-invocation-sentinel",
        "raw-connection-sentinel",
        "raw-argv-sentinel",
    ] {
        assert!(!debug.contains(raw), "raw audit value leaked: {raw}");
    }
}

#[test]
fn protocol_audit_remains_available() {
    let mut runtime = super::super::super::FixtureMcpRuntime::new(
        super::super::super::FixtureMcpMode::FixtureOnly,
        super::super::super::FixtureIdentity::new(
            crate::McpServerId::new("fixture-server").unwrap(),
            "1.0.0",
            "fixture-v1",
            "2025-11-25",
        )
        .unwrap(),
        vec![
            FixtureTool::new(
                "protocol",
                "1.0.0",
                "fixture",
                serde_json::json!({"type":"object","additionalProperties":false}),
                serde_json::json!({"type":"object","additionalProperties":false}),
            )
            .unwrap(),
        ],
        super::super::super::FixtureScript::new(vec![
            super::super::super::FixtureStep::response_at(0, serde_json::json!({})).unwrap(),
        ])
        .unwrap(),
        &["protocol"],
        super::super::super::FixtureLimits::default(),
        super::super::super::FixtureApprovalPolicy::FixtureDeterministicAllow,
        1,
    )
    .unwrap();
    runtime
        .initialize(super::super::super::FixtureInitialize::new(
            crate::McpRuntimeInstanceId::new("runtime-1").unwrap(),
            crate::McpSessionId::new("session-1").unwrap(),
            crate::McpConnectionId::new("connection-1").unwrap(),
            1,
            "fixture-server",
            "1.0.0",
            "fixture-v1",
            "2025-11-25",
        ))
        .unwrap();
    let publication = runtime.discover().unwrap();
    let mut capability = publication
        .issue_dispatch(
            "protocol",
            "invocation-1",
            serde_json::json!({}),
            "principal",
            "authority",
            10,
        )
        .unwrap();
    assert_eq!(
        runtime.dispatch(&mut capability, None),
        Ok(FixtureCallResult::Completed)
    );
    assert_eq!(
        runtime.try_audit().unwrap()[0].execution_class(),
        crate::McpToolExecutionClass::ProtocolOnly
    );
}
