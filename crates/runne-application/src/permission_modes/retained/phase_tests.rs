use super::{model::*, tests_support::*};
use crate::permission_modes::{
    ApprovalBinding, CompositeScopeDigest, ContainmentStrategy, FilesystemPermission,
    LocalInvocationLimitsV1, PermissionAction, PermissionMode, PermissionPolicyCompiler,
};
use runne_domain::task_run::{TaskRunExecutable, TaskRunLocalCommand};

fn before_go() -> RetainedPhaseObservationV1 {
    RetainedPhaseObservationV1 {
        phase: RetainedPhaseV1::BeforeGo,
        runtime_start: None,
        elapsed_runtime_ms: None,
    }
}

fn running(fixture: &Fixture, start: u64, elapsed: u64) -> RetainedPhaseObservationV1 {
    RetainedPhaseObservationV1 {
        phase: RetainedPhaseV1::Running,
        runtime_start: Some(RetainedRuntimeStartV1 {
            original_binding_digest: fixture.original.digest(),
            invocation_id: fixture.original.invocation_id(),
            clock_epoch: 50,
            monotonic_start_ms: start,
            wall_start_unix_ms: 100_000 + (start as i64 - 1_000),
        }),
        elapsed_runtime_ms: Some(elapsed),
    }
}

#[test]
fn missing_original_baseline_and_candidate_mutation_are_not_evaluable() {
    let mut fixture = Fixture::new();
    let mut input = fixture.input(before_go());
    input.original_context = None;
    assert_eq!(
        PermissionPolicyCompiler::evaluate_retained_v1(&input),
        RetainedPolicyEvaluationV1::NotEvaluable(
            RetainedNotEvaluableReasonV1::MissingOriginalContext
        )
    );
    fixture.candidate.target_version += 1;
    assert_eq!(
        PermissionPolicyCompiler::evaluate_retained_v1(&fixture.input(before_go())),
        RetainedPolicyEvaluationV1::NotEvaluable(
            RetainedNotEvaluableReasonV1::OriginalIdentityMismatch
        )
    );
}

#[test]
fn before_go_rejects_stray_runtime_fields_and_current_snapshot_corruption() {
    let fixture = Fixture::new();
    let stray = RetainedPhaseObservationV1 {
        runtime_start: Some(running(&fixture, 1_000, 100).runtime_start.unwrap()),
        ..before_go()
    };
    assert_eq!(
        PermissionPolicyCompiler::evaluate_retained_v1(&fixture.input(stray)),
        RetainedPolicyEvaluationV1::NotEvaluable(
            RetainedNotEvaluableReasonV1::PhaseObservationInconsistent
        )
    );
    let mut corrupted = Fixture::new();
    corrupted.current.app_policy_digest = digest(99);
    assert_eq!(
        PermissionPolicyCompiler::evaluate_retained_v1(&corrupted.input(before_go())),
        RetainedPolicyEvaluationV1::NotEvaluable(
            RetainedNotEvaluableReasonV1::CurrentFactsInconsistent
        )
    );
}

#[test]
fn independent_protected_root_and_native_owner_changes_do_not_follow_digest_bytes() {
    for change in 0..3 {
        let mut fixture = Fixture::new();
        match change {
            0 => fixture.current.coordinates.protected_generation += 1,
            1 => fixture.current.coordinates.root_generation += 1,
            _ => fixture.current.coordinates.native_boundary_owner_epoch += 1,
        }
        assert_eq!(
            PermissionPolicyCompiler::evaluate_retained_v1(&fixture.input(before_go())),
            RetainedPolicyEvaluationV1::NotEvaluable(
                RetainedNotEvaluableReasonV1::OwnerCompatibilityRequired
            )
        );
    }
}

#[test]
fn running_phase_requires_one_consistent_start_clock_and_stops_after_limit() {
    let fixture = Fixture::new();
    assert_eq!(
        PermissionPolicyCompiler::evaluate_retained_v1(&fixture.input(
            RetainedPhaseObservationV1 {
                phase: RetainedPhaseV1::Running,
                runtime_start: None,
                elapsed_runtime_ms: Some(1)
            }
        )),
        RetainedPolicyEvaluationV1::NotEvaluable(
            RetainedNotEvaluableReasonV1::ClockObservationInconsistent
        )
    );
    assert_eq!(
        PermissionPolicyCompiler::evaluate_retained_v1(
            &fixture.input(running(&fixture, 1_050, 49))
        ),
        RetainedPolicyEvaluationV1::NotEvaluable(
            RetainedNotEvaluableReasonV1::ClockObservationInconsistent
        )
    );
    assert!(matches!(
        PermissionPolicyCompiler::evaluate_retained_v1(
            &fixture.input(running(&fixture, 1_050, 50))
        ),
        RetainedPolicyEvaluationV1::PolicyCompatible { .. }
    ));
}

#[test]
fn full_to_risk_change_requires_approval_before_go_and_stop_after_go() {
    let mut fixture = Fixture::new();
    fixture.replace_current(full_allow_snapshot(), PermissionMode::RiskBased, 3);
    assert!(matches!(
        PermissionPolicyCompiler::evaluate_retained_v1(&fixture.input(before_go())),
        RetainedPolicyEvaluationV1::RequireApproval { .. }
    ));
    assert!(matches!(
        PermissionPolicyCompiler::evaluate_retained_v1(
            &fixture.input(running(&fixture, 1_050, 50))
        ),
        RetainedPolicyEvaluationV1::StopRequired { .. }
    ));
}

#[test]
fn terminal_observation_never_authorizes_continuation() {
    let fixture = Fixture::new();
    let terminal = RetainedPhaseObservationV1 {
        phase: RetainedPhaseV1::Terminal,
        ..running(&fixture, 1_050, 50)
    };
    assert!(!matches!(
        PermissionPolicyCompiler::evaluate_retained_v1(&fixture.input(terminal)),
        RetainedPolicyEvaluationV1::PolicyCompatible { .. }
    ));
}

#[test]
fn every_original_candidate_identity_component_is_exact() {
    macro_rules! reject_change {
        ($change:expr) => {{
            let mut fixture = Fixture::new();
            ($change)(&mut fixture.candidate);
            assert!(matches!(
                PermissionPolicyCompiler::evaluate_retained_v1(&fixture.input(before_go())),
                RetainedPolicyEvaluationV1::NotEvaluable(_)
            ));
        }};
    }
    reject_change!(|b: &mut ApprovalBinding| b.action = PermissionAction::FsWrite);
    reject_change!(|b: &mut ApprovalBinding| b.normalized_arguments_digest = digest(90));
    reject_change!(|b: &mut ApprovalBinding| b.tool_schema_digest = digest(91));
    reject_change!(|b: &mut ApprovalBinding| b.principal_id =
        runne_api::ApiPrincipalId::new("other-user").unwrap());
    reject_change!(|b: &mut ApprovalBinding| b.invocation.task_run_id =
        runne_domain::id::TaskRunId::from_bytes([21; 16]));
    reject_change!(|b: &mut ApprovalBinding| b.invocation.attempt_id =
        runne_domain::id::AttemptId::from_bytes([22; 16]));
    reject_change!(|b: &mut ApprovalBinding| b.invocation.invocation_id =
        runne_domain::id::InvocationId::from_bytes([23; 16]));
    reject_change!(|b: &mut ApprovalBinding| b.target_identity_digest = digest(92));
    reject_change!(|b: &mut ApprovalBinding| b.target_version += 1);
    reject_change!(|b: &mut ApprovalBinding| b.environment_digest = digest(93));
    reject_change!(|b: &mut ApprovalBinding| b.cwd_identity_digest = digest(94));
    reject_change!(|b: &mut ApprovalBinding| b.executable_digest = None);
    reject_change!(|b: &mut ApprovalBinding| b.composite_scope_digest =
        CompositeScopeDigest::from_bytes([95; 32]));
    reject_change!(
        |b: &mut ApprovalBinding| b.containment_version = ContainmentStrategy::WorkspaceBoundV1
    );
    reject_change!(|b: &mut ApprovalBinding| b.relevant_policy_digest = digest(96));
    reject_change!(|b: &mut ApprovalBinding| b.expires_at_unix_ms += 1);
}

#[test]
fn current_assignment_scope_command_limits_and_clock_must_match_the_frozen_original() {
    let mut fixture = Fixture::new();
    fixture.current.coordinates.assignment.fence.0 += 1;
    assert!(!matches!(
        PermissionPolicyCompiler::evaluate_retained_v1(&fixture.input(before_go())),
        RetainedPolicyEvaluationV1::PolicyCompatible { .. }
    ));
    let mut fixture = Fixture::new();
    fixture.current.coordinates.principal_id = runne_api::ApiPrincipalId::new("different").unwrap();
    assert!(!matches!(
        PermissionPolicyCompiler::evaluate_retained_v1(&fixture.input(before_go())),
        RetainedPolicyEvaluationV1::PolicyCompatible { .. }
    ));
    let mut fixture = Fixture::new();
    fixture
        .current
        .scope
        .filesystem
        .permissions
        .remove(&FilesystemPermission::Delete);
    assert!(!matches!(
        PermissionPolicyCompiler::evaluate_retained_v1(&fixture.input(before_go())),
        RetainedPolicyEvaluationV1::PolicyCompatible { .. }
    ));
    let mut fixture = Fixture::new();
    fixture.current.limits = LocalInvocationLimitsV1::checked(2048, 1024, 120_000).unwrap();
    assert!(!matches!(
        PermissionPolicyCompiler::evaluate_retained_v1(&fixture.input(before_go())),
        RetainedPolicyEvaluationV1::PolicyCompatible { .. }
    ));
    let mut fixture = Fixture::new();
    let changed_command = TaskRunLocalCommand::new(
        TaskRunExecutable::workspace_relative("bin/other".into()).unwrap(),
        ".".into(),
        vec!["tool".into(), "--check".into()],
        vec![("MODE".into(), "test".into())],
    )
    .unwrap();
    fixture.current.command_intent_digest =
        runne_domain::id::IntegrityDigest::from_bytes(changed_command.intent_digest());
    fixture.current.command = changed_command;
    assert!(!matches!(
        PermissionPolicyCompiler::evaluate_retained_v1(&fixture.input(before_go())),
        RetainedPolicyEvaluationV1::PolicyCompatible { .. }
    ));
    let mut fixture = Fixture::new();
    fixture.current.observed_clock = RetainedClockObservationV1 {
        epoch: 51,
        wall_unix_ms: 100_100,
        monotonic_ms: 1_100,
    };
    assert_eq!(
        PermissionPolicyCompiler::evaluate_retained_v1(&fixture.input(before_go())),
        RetainedPolicyEvaluationV1::NotEvaluable(
            RetainedNotEvaluableReasonV1::ClockObservationInconsistent
        )
    );
}

#[test]
fn independent_project_workspace_root_claim_and_assignment_coordinates_must_match() {
    for change in 0..7 {
        let mut fixture = Fixture::new();
        match change {
            0 => fixture.current.coordinates.project_version += 1,
            1 => fixture.current.coordinates.workspace_version += 1,
            2 => fixture.current.coordinates.admitted_root_version += 1,
            3 => fixture.current.coordinates.claim_stream_version += 1,
            4 => fixture.current.coordinates.assignment.node_epoch += 1,
            5 => fixture.current.coordinates.assignment.node_id.0 = "node-b".into(),
            _ => fixture.current.coordinates.held_root_identity_digest = digest(98),
        }
        assert!(!matches!(
            PermissionPolicyCompiler::evaluate_retained_v1(&fixture.input(before_go())),
            RetainedPolicyEvaluationV1::PolicyCompatible { .. }
        ));
    }
}

#[test]
fn expired_deadline_wall_rollback_and_runtime_limit_never_remain_compatible() {
    let mut expired = Fixture::new();
    expired.current.observed_clock.wall_unix_ms = 800_000;
    assert!(!matches!(
        PermissionPolicyCompiler::evaluate_retained_v1(&expired.input(before_go())),
        RetainedPolicyEvaluationV1::PolicyCompatible { .. }
    ));
    let mut rollback = Fixture::new();
    rollback.current.observed_clock.wall_unix_ms = 99_999;
    assert_eq!(
        PermissionPolicyCompiler::evaluate_retained_v1(&rollback.input(before_go())),
        RetainedPolicyEvaluationV1::NotEvaluable(
            RetainedNotEvaluableReasonV1::ClockObservationInconsistent
        )
    );
    let mut elapsed = Fixture::new();
    elapsed.current.observed_clock = RetainedClockObservationV1 {
        epoch: 50,
        wall_unix_ms: 220_000,
        monotonic_ms: 121_000,
    };
    assert!(matches!(
        PermissionPolicyCompiler::evaluate_retained_v1(
            &elapsed.input(running(&elapsed, 1_000, 120_000))
        ),
        RetainedPolicyEvaluationV1::StopRequired { .. }
    ));
}
