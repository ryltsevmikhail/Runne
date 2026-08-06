use super::super::super::authorization::{
    AuthorizationReplayGuard, approval_scope, approve, authorization_replay_key, issue_capability,
    validate_authorization,
};
use super::super::super::context::current_context;
use super::super::support::{
    approver, baseline, binding_parts, capability, cwd, executable, intent,
};

#[test]
fn authorization_replay_key_covers_guard_capability_approval_digest_binding_revision_and_epoch() {
    let baseline_intent = baseline();
    let authority = approver(20);
    let replay_guard = AuthorizationReplayGuard::new([1; 16]);
    let capability_id = capability(21);
    let issued_capability = issue_capability(
        capability_id.clone(),
        &replay_guard,
        &baseline_intent,
        2,
        1,
        1,
    );
    let approval = approve(
        &baseline_intent,
        approval_scope(&baseline_intent),
        authority,
        2,
        1,
        1,
        true,
    );
    let key = authorization_replay_key(&issued_capability, &approval, &baseline_intent);
    assert!(key.windows(16).any(|part| part == replay_guard.id()));
    assert!(key.windows(16).any(|part| part == capability_id.bytes()));
    assert!(
        key.windows(32)
            .any(|part| part == baseline_intent.digest().as_bytes())
    );
    let other = intent(
        binding_parts(9, 2, 3, 4, 5, 6),
        13,
        executable(9, 2, 3, 4, 1),
        11,
        cwd(5, 6, 7, 1),
        12,
    );
    let other_approval = approve(&other, approval_scope(&other), approver(20), 2, 1, 1, true);
    assert_ne!(
        key,
        authorization_replay_key(
            &issue_capability(
                capability(21),
                &AuthorizationReplayGuard::new([2; 16]),
                &baseline_intent,
                2,
                1,
                1
            ),
            &approval,
            &baseline_intent
        )
    );
    assert_ne!(
        key,
        authorization_replay_key(
            &issue_capability(capability(22), &replay_guard, &baseline_intent, 2, 1, 1),
            &approval,
            &baseline_intent
        )
    );
    assert_ne!(
        key,
        authorization_replay_key(&issued_capability, &other_approval, &baseline_intent)
    );
    assert_ne!(
        key,
        authorization_replay_key(&issued_capability, &approval, &other)
    );
    assert_ne!(
        key,
        authorization_replay_key(
            &issue_capability(capability(21), &replay_guard, &other, 2, 1, 1),
            &approval,
            &baseline_intent
        )
    );
    assert_ne!(
        key,
        authorization_replay_key(
            &issue_capability(capability(21), &replay_guard, &baseline_intent, 2, 2, 1),
            &approval,
            &baseline_intent
        )
    );
    assert_ne!(
        key,
        authorization_replay_key(
            &issue_capability(capability(21), &replay_guard, &baseline_intent, 2, 1, 2),
            &approval,
            &baseline_intent
        )
    );
}

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
