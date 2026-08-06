use super::super::super::ProcessContractError;
use super::super::super::authorization::{
    AuthorizationReplayGuard, approval_scope, approve, issue_capability, validate_authorization,
};
use super::super::super::context::current_context;
use super::super::support::{approver, baseline, capability};

#[test]
fn replay_guard_snapshot_round_trip_preserves_replay_rejection() {
    let intent = baseline();
    let mut replay_guard = AuthorizationReplayGuard::new([1; 16]);
    let authority = approver(20);
    let capability = issue_capability(capability(21), &replay_guard, &intent, 2, 1, 1);
    let approval = approve(
        &intent,
        approval_scope(&intent),
        authority.clone(),
        2,
        1,
        1,
        true,
    );
    let current = current_context(&intent, authority, 1, 1);
    assert!(
        validate_authorization(
            intent.clone(),
            Some(&capability),
            Some(&approval),
            &current,
            &mut replay_guard,
            1
        )
        .is_ok()
    );
    let snapshot = replay_guard.snapshot();
    let mut reopened = AuthorizationReplayGuard::reopen(snapshot);
    assert!(matches!(
        validate_authorization(
            intent.clone(),
            Some(&capability),
            Some(&approval),
            &current,
            &mut reopened,
            1
        ),
        Err(ProcessContractError::CapabilityInvalid)
    ));
    let mut fresh = AuthorizationReplayGuard::new([2; 16]);
    assert!(matches!(
        validate_authorization(
            intent,
            Some(&capability),
            Some(&approval),
            &current,
            &mut fresh,
            1
        ),
        Err(ProcessContractError::CapabilityInvalid)
    ));
}

#[test]
fn exact_valid_authorization_is_recorded_once() {
    let intent = baseline();
    let mut replay_guard = AuthorizationReplayGuard::new([1; 16]);
    let authority = approver(20);
    let capability = issue_capability(capability(21), &replay_guard, &intent, 2, 1, 1);
    let approval = approve(
        &intent,
        approval_scope(&intent),
        authority.clone(),
        2,
        1,
        1,
        true,
    );
    let current = current_context(&intent, authority, 1, 1);
    assert!(
        validate_authorization(
            intent.clone(),
            Some(&capability),
            Some(&approval),
            &current,
            &mut replay_guard,
            1
        )
        .is_ok()
    );
    assert!(matches!(
        validate_authorization(
            intent,
            Some(&capability),
            Some(&approval),
            &current,
            &mut replay_guard,
            1
        ),
        Err(ProcessContractError::CapabilityInvalid)
    ));
}

#[test]
fn replay_guard_id_mismatch_is_denied() {
    let intent = baseline();
    let authority = approver(20);
    let issued_replay_guard = AuthorizationReplayGuard::new([1; 16]);
    let mut current_replay_guard = AuthorizationReplayGuard::new([2; 16]);
    let capability = issue_capability(capability(21), &issued_replay_guard, &intent, 2, 1, 1);
    let approval = approve(
        &intent,
        approval_scope(&intent),
        authority.clone(),
        2,
        1,
        1,
        true,
    );
    let current = current_context(&intent, authority, 1, 1);
    assert!(matches!(
        validate_authorization(
            intent,
            Some(&capability),
            Some(&approval),
            &current,
            &mut current_replay_guard,
            1
        ),
        Err(ProcessContractError::CapabilityInvalid)
    ));
}

#[test]
fn capability_and_approval_are_required_and_expire_at_their_deadline() {
    let intent = baseline();
    let authority = approver(20);
    let mut replay_guard = AuthorizationReplayGuard::new([1; 16]);
    let expired_capability = issue_capability(capability(21), &replay_guard, &intent, 1, 1, 1);
    let approval = approve(
        &intent,
        approval_scope(&intent),
        authority.clone(),
        2,
        1,
        1,
        true,
    );
    let current = current_context(&intent, authority, 1, 1);
    assert!(matches!(
        validate_authorization(
            intent.clone(),
            None,
            Some(&approval),
            &current,
            &mut replay_guard,
            0
        ),
        Err(ProcessContractError::CapabilityInvalid)
    ));
    assert!(matches!(
        validate_authorization(
            intent.clone(),
            Some(&expired_capability),
            None,
            &current,
            &mut replay_guard,
            0
        ),
        Err(ProcessContractError::ApprovalInvalid)
    ));
    assert!(matches!(
        validate_authorization(
            intent.clone(),
            Some(&expired_capability),
            Some(&approval),
            &current,
            &mut replay_guard,
            1
        ),
        Err(ProcessContractError::CapabilityInvalid)
    ));
    let valid_capability = issue_capability(capability(22), &replay_guard, &intent, 2, 1, 1);
    let expired_approval = approve(
        &intent,
        approval_scope(&intent),
        approver(20),
        1,
        1,
        1,
        true,
    );
    assert!(matches!(
        validate_authorization(
            intent,
            Some(&valid_capability),
            Some(&expired_approval),
            &current,
            &mut replay_guard,
            1
        ),
        Err(ProcessContractError::ApprovalInvalid)
    ));
}

#[test]
fn rejected_approval_does_not_record_authorization() {
    let intent = baseline();
    let authority = approver(20);
    let mut replay_guard = AuthorizationReplayGuard::new([1; 16]);
    let capability = issue_capability(capability(21), &replay_guard, &intent, 2, 1, 1);
    let rejected = approve(
        &intent,
        approval_scope(&intent),
        authority.clone(),
        2,
        1,
        1,
        false,
    );
    let approved = approve(
        &intent,
        approval_scope(&intent),
        authority.clone(),
        2,
        1,
        1,
        true,
    );
    let current = current_context(&intent, authority, 1, 1);
    assert!(matches!(
        validate_authorization(
            intent.clone(),
            Some(&capability),
            Some(&rejected),
            &current,
            &mut replay_guard,
            1
        ),
        Err(ProcessContractError::ApprovalInvalid)
    ));
    assert!(
        validate_authorization(
            intent,
            Some(&capability),
            Some(&approved),
            &current,
            &mut replay_guard,
            1
        )
        .is_ok()
    );
}
