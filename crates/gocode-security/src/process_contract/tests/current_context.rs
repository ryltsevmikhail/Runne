use super::super::ProcessContractError;
use super::super::authorization::{
    AuthorizationReplayGuard, approval_scope, approve, issue_capability, validate_authorization,
};
use super::super::context::current_context;
use super::support::{approver, baseline, binding_parts, capability, cwd, executable, intent};

pub(super) fn assert_context_error(
    current_intent: super::super::ProcessIntentV1,
    expected: ProcessContractError,
) {
    let intent = baseline();
    let authority = approver(20);
    let mut replay_guard = AuthorizationReplayGuard::new([1; 16]);
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
    let mismatched = current_context(&current_intent, authority.clone(), 1, 1);
    match validate_authorization(
        intent.clone(),
        Some(&capability),
        Some(&approval),
        &mismatched,
        &mut replay_guard,
        1,
    ) {
        Err(error) => assert_eq!(error, expected),
        Ok(_) => panic!("mismatched current context was admitted"),
    }
    let current = current_context(&intent, authority, 1, 1);
    assert!(
        validate_authorization(
            intent,
            Some(&capability),
            Some(&approval),
            &current,
            &mut replay_guard,
            1
        )
        .is_ok()
    );
}

macro_rules! identity_mismatch {
    ($name:ident, $changed:expr) => {
        #[test]
        fn $name() {
            assert_context_error($changed, ProcessContractError::CapabilityInvalid);
        }
    };
}

identity_mismatch!(
    principal_mismatch_is_denied,
    intent(
        binding_parts(9, 2, 3, 4, 5, 6),
        10,
        executable(1, 2, 3, 4, 1),
        11,
        cwd(5, 6, 7, 1),
        12
    )
);
identity_mismatch!(
    authority_mismatch_is_denied,
    intent(
        binding_parts(1, 9, 3, 4, 5, 6),
        10,
        executable(1, 2, 3, 4, 1),
        11,
        cwd(5, 6, 7, 1),
        12
    )
);
identity_mismatch!(
    owner_mismatch_is_denied,
    intent(
        binding_parts(1, 2, 9, 4, 5, 6),
        10,
        executable(1, 2, 3, 4, 1),
        11,
        cwd(5, 6, 7, 1),
        12
    )
);
identity_mismatch!(
    attempt_mismatch_is_denied,
    intent(
        binding_parts(1, 2, 3, 9, 5, 6),
        10,
        executable(1, 2, 3, 4, 1),
        11,
        cwd(5, 6, 7, 1),
        12
    )
);
identity_mismatch!(
    session_mismatch_is_denied,
    intent(
        binding_parts(1, 2, 3, 4, 9, 6),
        10,
        executable(1, 2, 3, 4, 1),
        11,
        cwd(5, 6, 7, 1),
        12
    )
);
identity_mismatch!(
    generation_mismatch_is_denied,
    intent(
        binding_parts(1, 2, 3, 4, 5, 9),
        10,
        executable(1, 2, 3, 4, 1),
        11,
        cwd(5, 6, 7, 1),
        12
    )
);

fn assert_current_metadata_denied(revision: u64, epoch: u64) {
    let intent = baseline();
    let authority = approver(20);
    let mut replay_guard = AuthorizationReplayGuard::new([1; 16]);
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
    let current = current_context(&intent, authority, revision, epoch);
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
fn policy_revision_mismatch_is_denied() {
    assert_current_metadata_denied(2, 1);
}

#[test]
fn auth_epoch_mismatch_is_denied() {
    assert_current_metadata_denied(1, 2);
}

mod verification;
