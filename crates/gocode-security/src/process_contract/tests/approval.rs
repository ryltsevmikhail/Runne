use super::super::ProcessContractError;
use super::super::authorization::{
    AuthorizationReplayGuard, ProcessApprovalV1, approval_scope, approve, issue_capability,
    validate_authorization,
};
use super::super::context::current_context;
use super::support::{approver, baseline, binding_parts, capability, cwd, executable, intent};

fn assert_approval_denied(approval: ProcessApprovalV1, current_approver: u8) {
    let intent = baseline();
    let mut replay_guard = AuthorizationReplayGuard::new([1; 16]);
    let capability = issue_capability(capability(21), &replay_guard, &intent, 2, 1, 1);
    let current = current_context(&intent, approver(current_approver), 1, 1);
    assert!(matches!(
        validate_authorization(
            intent,
            Some(&capability),
            Some(&approval),
            &current,
            &mut replay_guard,
            1
        ),
        Err(ProcessContractError::ApprovalInvalid)
    ));
}

#[test]
fn approval_id_mismatch_is_denied() {
    let other = intent(
        binding_parts(1, 2, 3, 4, 5, 6),
        13,
        executable(1, 2, 3, 4, 1),
        11,
        cwd(5, 6, 7, 1),
        12,
    );
    assert_approval_denied(
        approve(&other, approval_scope(&other), approver(20), 2, 1, 1, true),
        20,
    );
}

#[test]
fn approval_digest_mismatch_is_denied() {
    let other = intent(
        binding_parts(1, 2, 3, 4, 5, 6),
        10,
        executable(9, 2, 3, 4, 1),
        11,
        cwd(5, 6, 7, 1),
        12,
    );
    assert_approval_denied(
        approve(&other, approval_scope(&other), approver(20), 2, 1, 1, true),
        20,
    );
}

#[test]
fn approval_binding_mismatch_is_denied() {
    let other = intent(
        binding_parts(9, 2, 3, 4, 5, 6),
        10,
        executable(1, 2, 3, 4, 1),
        11,
        cwd(5, 6, 7, 1),
        12,
    );
    assert_approval_denied(
        approve(&other, approval_scope(&other), approver(20), 2, 1, 1, true),
        20,
    );
}

#[test]
fn immutable_approver_identity_mismatch_is_denied() {
    let intent = baseline();
    assert_approval_denied(
        approve(
            &intent,
            approval_scope(&intent),
            approver(21),
            2,
            1,
            1,
            true,
        ),
        20,
    );
}

#[test]
fn closed_approval_scope_mismatch_is_denied() {
    let baseline_intent = baseline();
    let other = intent(
        binding_parts(1, 2, 3, 4, 5, 6),
        10,
        executable(9, 2, 3, 4, 1),
        11,
        cwd(5, 6, 7, 1),
        12,
    );
    assert_approval_denied(
        approve(
            &baseline_intent,
            approval_scope(&other),
            approver(20),
            2,
            1,
            1,
            true,
        ),
        20,
    );
}
