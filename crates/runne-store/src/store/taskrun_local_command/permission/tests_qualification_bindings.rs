//! Checked typed binding correlation negatives, not independent native identity branch coverage.
use super::{ceremony, fixture::Fixture, support::Case, target};
use runne_application::{permission_modes::*, ports::EventStoreError};
use runne_domain::id::{AttemptId, IntegrityDigest, InvocationId, TaskRunId};

fn input(b: &LocalCommandPermissionBindingV1) -> LocalCommandPermissionBindingInputV1 {
    LocalCommandPermissionBindingInputV1 {
        selection: b.selection().clone(),
        assignment: b.assignment().clone(),
        claim_stream_version: b.claim_stream_version(),
        invocation_id: b.invocation_id(),
        project_id: b.project_id(),
        project_version: b.project_version(),
        workspace_version: b.workspace_version(),
        admitted_root_version: b.admitted_root_version(),
        held_root_identity_digest: b.held_root_identity_digest(),
        command: b.command().clone(),
        command_intent_digest: b.command_intent_digest(),
        approval: b.approval().clone(),
        scope: b.scope().clone(),
        closed_rules_snapshot: b.closed_rules_snapshot(),
        closed_rules_digest: b.closed_rules_digest(),
        limits: b.limits(),
    }
}

#[test]
fn valid_typed_identity_variants_refuse_original_capture_without_spent() {
    let c = Case::new(true);
    assert_eq!(
        c.f.store
            .observe_local_command_permission_policy(&c.b)
            .unwrap(),
        None
    );
    for dimension in 0..17 {
        let mut value = input(&c.b);
        match dimension {
            0 => value.approval.target_version += 1,
            1 => value.approval.target_identity_digest = IntegrityDigest::from_bytes([0x71; 32]),
            2 => value.approval.environment_digest = IntegrityDigest::from_bytes([0x72; 32]),
            3 => value.project_version += 1,
            4 => value.workspace_version += 1,
            5 => value.admitted_root_version += 1,
            6 => value.held_root_identity_digest = IntegrityDigest::from_bytes([0x73; 32]),
            7 => value.assignment.fence.0 += 1,
            8 => value.assignment.node_epoch += 1,
            9 => value.assignment.node_id.0 = uuid::Uuid::now_v7().to_string(),
            10 => {
                value.assignment.taskrun_id =
                    TaskRunId::from_bytes(uuid::Uuid::now_v7().into_bytes());
                value.approval.invocation.task_run_id = value.assignment.taskrun_id;
            }
            11 => {
                value.assignment.attempt_id =
                    AttemptId::from_bytes(uuid::Uuid::now_v7().into_bytes());
                value.approval.invocation.attempt_id = value.assignment.attempt_id;
            }
            12 => {
                value.invocation_id = InvocationId::from_bytes(uuid::Uuid::now_v7().into_bytes());
                value.approval.invocation.invocation_id = value.invocation_id;
            }
            13 => value.approval.expires_at_unix_ms += 1,
            14 => value.scope.lifetime_ms -= 1,
            15 => {
                value.selection.scope.principal_id =
                    runne_api::ApiPrincipalId::new("different-owner").unwrap();
                value.approval.principal_id = value.selection.scope.principal_id.clone();
            }
            16 => value
                .selection
                .scope
                .runtime_authority_id
                .0
                .push_str("-other"),
            _ => unreachable!(),
        }
        value.scope.permission_scope = value.selection.scope.clone();
        value.approval.composite_scope_digest = value.scope.digest().unwrap();
        let different = LocalCommandPermissionBindingV1::checked(value)
            .unwrap_or_else(|e| panic!("dimension {dimension} must be valid typed data: {e:?}"));
        assert_ne!(different.digest(), c.b.digest());
        assert!(
            c.f.store
                .observe_local_command_permission_policy(&different)
                .is_err(),
            "dimension {dimension}"
        );
        assert_eq!(c.spent_on_owned_reopen(), 0);
    }
    // Original remains admissible after every refused typed variant; actual shared callback once.
    let lease = c.lease();
    c.burn(lease.as_ref()).unwrap();
    assert_eq!(c.release_model(lease.as_ref(), 0), (Ok(()), 1));
}

#[test]
fn actual_expired_original_capture_is_not_renewed_by_current_policy() {
    let f = Fixture::new();
    ceremony::commit(&f, PermissionMode::RiskBased, 0);
    let (original, prepared) = target::prepare(&f);
    let mut value = input(&original);
    let original_deadline = super::fixture::now() - 1000;
    value.approval.expires_at_unix_ms = original_deadline;
    let expired = LocalCommandPermissionBindingV1::checked(value).unwrap();
    // No authority rows or native observation are fabricated; expiration is original typed data.
    f.store
        .capture_local_command_permission(&expired, prepared.observation())
        .unwrap();
    assert_eq!(
        f.store
            .observe_local_command_permission_policy(&expired)
            .unwrap(),
        Some(5)
    );
    assert_eq!(
        f.store.admit_local_command_permission(&expired, None),
        Err(EventStoreError::CorruptData)
    );
    ceremony::commit(&f, PermissionMode::RiskBased, 1);
    assert_eq!(
        f.store
            .observe_local_command_permission_policy(&expired)
            .unwrap(),
        Some(5)
    );
    assert_eq!(expired.approval().expires_at_unix_ms, original_deadline);
    let capture = f
        .store
        .load_local_command_permission_capture(expired.assignment().taskrun_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        capture.canonical_binding_digest,
        *expired.digest().as_bytes()
    );
}
