use super::super::super::authorization::{
    AuthorizationReplayGuard, approval_scope, approve, issue_capability, validate_authorization,
};
use super::super::super::context::current_context;
use super::super::support::{approver, baseline, capability};

#[test]
fn distinct_capability_ids_for_one_intent_record_independently() {
    let intent = baseline();
    let authority = approver(20);
    let mut replay_guard = AuthorizationReplayGuard::new([1; 16]);
    let first = issue_capability(capability(21), &replay_guard, &intent, 2, 1, 1);
    let second = issue_capability(capability(22), &replay_guard, &intent, 2, 1, 1);
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
            Some(&first),
            Some(&approval),
            &current,
            &mut replay_guard,
            1
        )
        .is_ok()
    );
    assert!(
        validate_authorization(
            intent,
            Some(&second),
            Some(&approval),
            &current,
            &mut replay_guard,
            1
        )
        .is_ok()
    );
}
