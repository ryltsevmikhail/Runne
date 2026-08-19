use super::super::super::ProcessContractError;
use super::super::super::authorization::{
    AuthorizationReplayDomainV1, AuthorizationReplayGuard, approval_scope, approve_bound,
    issue_capability, validate_authorization,
};
use super::super::super::context::current_context;
use super::super::support::{approver, baseline, capability};

#[test]
fn replay_guard_rejects_reuse_without_a_cloned_snapshot() {
    let intent = baseline();
    let mut replay_guard =
        AuthorizationReplayGuard::new(AuthorizationReplayDomainV1::new([1; 16], 1));
    let authority = approver(20);
    let capability = issue_capability(capability(21), &replay_guard, &intent, 2, 1, 1);
    let current = current_context(&intent, authority, 1, 1);
    let approval = approve_bound(
        &intent,
        approval_scope(&intent),
        &replay_guard,
        &current,
        2,
        true,
    );
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
            intent.clone(),
            Some(&capability),
            Some(&approval),
            &current,
            &mut replay_guard,
            1
        ),
        Err(ProcessContractError::CapabilityInvalid)
    ));
    let mut fresh = AuthorizationReplayGuard::new(AuthorizationReplayDomainV1::new([2; 16], 2));
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
    let mut replay_guard =
        AuthorizationReplayGuard::new(AuthorizationReplayDomainV1::new([1; 16], 1));
    let authority = approver(20);
    let capability = issue_capability(capability(21), &replay_guard, &intent, 2, 1, 1);
    let current = current_context(&intent, authority, 1, 1);
    let approval = approve_bound(
        &intent,
        approval_scope(&intent),
        &replay_guard,
        &current,
        2,
        true,
    );
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
    let issued_replay_guard =
        AuthorizationReplayGuard::new(AuthorizationReplayDomainV1::new([1; 16], 1));
    let mut current_replay_guard =
        AuthorizationReplayGuard::new(AuthorizationReplayDomainV1::new([2; 16], 2));
    let capability = issue_capability(capability(21), &issued_replay_guard, &intent, 2, 1, 1);
    let current = current_context(&intent, authority, 1, 1);
    let approval = approve_bound(
        &intent,
        approval_scope(&intent),
        &issued_replay_guard,
        &current,
        2,
        true,
    );
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
    let mut replay_guard =
        AuthorizationReplayGuard::new(AuthorizationReplayDomainV1::new([1; 16], 1));
    let expired_capability = issue_capability(capability(21), &replay_guard, &intent, 1, 1, 1);
    let current = current_context(&intent, authority, 1, 1);
    let approval = approve_bound(
        &intent,
        approval_scope(&intent),
        &replay_guard,
        &current,
        2,
        true,
    );
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
    let expired_approval = approve_bound(
        &intent,
        approval_scope(&intent),
        &replay_guard,
        &current,
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
    let mut replay_guard =
        AuthorizationReplayGuard::new(AuthorizationReplayDomainV1::new([1; 16], 1));
    let capability = issue_capability(capability(21), &replay_guard, &intent, 2, 1, 1);
    let current = current_context(&intent, authority, 1, 1);
    let rejected = approve_bound(
        &intent,
        approval_scope(&intent),
        &replay_guard,
        &current,
        2,
        false,
    );
    let approved = approve_bound(
        &intent,
        approval_scope(&intent),
        &replay_guard,
        &current,
        2,
        true,
    );
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
