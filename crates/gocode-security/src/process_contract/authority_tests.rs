use std::sync::Arc;
use std::thread;

use gocode_platform_ports::process::{
    HeldFileIdentityV1, HeldProcessTreeHandleV1, ProcessAttemptIdV1, ProcessFileKindV1,
    ProcessGenerationIdV1, ProcessLifecycleBindingV1, ProcessOwnerIdV1, ProcessSessionIdV1,
    ProcessSymlinkProofV1, VerifiedCwdV1, VerifiedExecutableV1,
};

use super::{
    AllowedRootId, ApprovalId, ApproverId, AuthorityId, BoundedArgvV1, CapabilityGrantId,
    ExecutablePolicyId, ExplicitEnvironmentV1, InputBoundsV1, PortableUtf8V1, PrincipalId,
    ProcessAuthorizationAuthorityV1, ProcessContractError, ProcessIdentityBindingV1,
    ProcessIntentV1, ProcessIoBoundsV1, SandboxId, StdinPolicyV1,
};

fn id(value: u8) -> [u8; 16] {
    [value; 16]
}

pub(super) fn lifecycle(value: u8) -> ProcessLifecycleBindingV1 {
    ProcessLifecycleBindingV1::new(
        ProcessOwnerIdV1::new(id(value)).unwrap(),
        ProcessAttemptIdV1::new(id(value + 1)).unwrap(),
        ProcessSessionIdV1::new(id(value + 2)).unwrap(),
        ProcessGenerationIdV1::new(id(value + 3)).unwrap(),
        HeldProcessTreeHandleV1::new(id(value + 4)).unwrap(),
    )
}

fn file(value: u8) -> HeldFileIdentityV1 {
    HeldFileIdentityV1::new(id(value), [value; 32], [value + 1; 32], [value + 2; 32], 1).unwrap()
}

pub(super) fn authority() -> ProcessAuthorizationAuthorityV1 {
    let executable = VerifiedExecutableV1::new(
        file(1),
        ProcessFileKindV1::RegularFile,
        ProcessSymlinkProofV1::VerifiedNotSymlink,
    )
    .unwrap();
    let cwd = VerifiedCwdV1::new(
        file(2),
        ProcessFileKindV1::Directory,
        ProcessSymlinkProofV1::VerifiedNotSymlink,
    )
    .unwrap();
    ProcessAuthorizationAuthorityV1::new(
        executable,
        ExecutablePolicyId::new(id(3)).unwrap(),
        cwd,
        AllowedRootId::new(id(4)).unwrap(),
        PrincipalId::new(id(5)).unwrap(),
        AuthorityId::new(id(6)).unwrap(),
        CapabilityGrantId::new(id(7)).unwrap(),
        SandboxId::new(id(8)).unwrap(),
        ApproverId::new(id(9)).unwrap(),
        1,
        1,
        id(10),
    )
    .unwrap()
}

pub(super) fn intent(lifecycle: ProcessLifecycleBindingV1, approval: u8) -> ProcessIntentV1 {
    let executable = VerifiedExecutableV1::new(
        file(1),
        ProcessFileKindV1::RegularFile,
        ProcessSymlinkProofV1::VerifiedNotSymlink,
    )
    .unwrap();
    let cwd = VerifiedCwdV1::new(
        file(2),
        ProcessFileKindV1::Directory,
        ProcessSymlinkProofV1::VerifiedNotSymlink,
    )
    .unwrap();
    ProcessIntentV1::new(
        ApprovalId::new(id(approval)).unwrap(),
        executable,
        ExecutablePolicyId::new(id(3)).unwrap(),
        cwd,
        AllowedRootId::new(id(4)).unwrap(),
        BoundedArgvV1::new(
            vec![PortableUtf8V1::from_bytes(b"tool".to_vec()).unwrap()],
            InputBoundsV1::new(1, 4, 4).unwrap(),
        )
        .unwrap(),
        ExplicitEnvironmentV1::empty(),
        StdinPolicyV1::closed(),
        ProcessIoBoundsV1::new(4, 4, 8, 1, true).unwrap(),
        ProcessIdentityBindingV1::new(
            PrincipalId::new(id(5)).unwrap(),
            AuthorityId::new(id(6)).unwrap(),
            lifecycle.owner().clone(),
            lifecycle.attempt().clone(),
            lifecycle.session().clone(),
            lifecycle.generation().clone(),
            CapabilityGrantId::new(id(7)).unwrap(),
            SandboxId::new(id(8)).unwrap(),
            lifecycle.tree_handle().clone(),
        ),
    )
    .unwrap()
}

#[test]
fn child_boundaries_share_global_capability_ids_and_validate_exact_intents() {
    let authority = authority();
    let first_lifecycle = lifecycle(20);
    let second_lifecycle = lifecycle(30);
    let first = authority.bind_call(first_lifecycle.clone()).unwrap();
    let second = authority.bind_call(second_lifecycle.clone()).unwrap();
    let first_intent = intent(first_lifecycle, 40);
    let second_intent = intent(second_lifecycle, 41);

    let first_capability = first.issue_capability(&first_intent, 20).unwrap();
    let second_capability = second.issue_capability(&second_intent, 20).unwrap();
    assert_ne!(first_capability.id_label(), second_capability.id_label());
    let first_approval = first.approve(&first_intent, 20, true).unwrap();
    let second_approval = second.approve(&second_intent, 20, true).unwrap();
    assert!(
        first
            .validate(
                first_intent,
                Some(&first_capability),
                Some(&first_approval),
                10
            )
            .is_ok()
    );
    assert!(
        second
            .validate(
                second_intent,
                Some(&second_capability),
                Some(&second_approval),
                10
            )
            .is_ok()
    );
}

#[test]
fn mismatched_approval_does_not_consume_shared_replay_tuple() {
    let authority = authority();
    let call = lifecycle(20);
    let boundary = authority.bind_call(call.clone()).unwrap();
    let first = intent(call.clone(), 40);
    let second = intent(call, 41);
    let capability = boundary.issue_capability(&first, 20).unwrap();
    let mismatched = boundary.approve(&second, 20, true).unwrap();

    assert!(matches!(
        boundary.validate(first.clone(), Some(&capability), Some(&mismatched), 10),
        Err(ProcessContractError::ApprovalInvalid)
    ));
    let valid = boundary.approve(&first, 20, true).unwrap();
    assert!(
        boundary
            .validate(first, Some(&capability), Some(&valid), 10)
            .is_ok()
    );
}

#[test]
fn concurrent_unique_calls_issue_distinct_ids_and_replay_once_per_tuple() {
    let authority = authority();
    let mut workers = Vec::new();
    for offset in 0..8 {
        let authority = authority.clone();
        workers.push(thread::spawn(move || {
            let call = lifecycle(20 + offset * 5);
            let intent = intent(call.clone(), 40 + offset);
            authority
                .bind_call(call)
                .unwrap()
                .issue_capability(&intent, 20)
                .unwrap()
                .id_label()
        }));
    }
    let mut ids: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 8);

    let call = lifecycle(80);
    let boundary = Arc::new(authority.bind_call(call.clone()).unwrap());
    let intent = Arc::new(intent(call, 90));
    let capability = Arc::new(boundary.issue_capability(&intent, 20).unwrap());
    let approval = Arc::new(boundary.approve(&intent, 20, true).unwrap());
    let mut workers = Vec::new();
    for _ in 0..2 {
        let boundary = Arc::clone(&boundary);
        let intent = Arc::clone(&intent);
        let capability = Arc::clone(&capability);
        let approval = Arc::clone(&approval);
        workers.push(thread::spawn(move || {
            boundary
                .validate((*intent).clone(), Some(&capability), Some(&approval), 10)
                .is_ok()
        }));
    }
    assert_eq!(
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|ok| *ok)
            .count(),
        1
    );
}

#[test]
fn dropped_advance_aborts_and_committed_advance_fences_old_children() {
    let authority = authority();
    let old_lifecycle = lifecycle(20);
    let old = authority.bind_call(old_lifecycle.clone()).unwrap();
    let old_intent = intent(old_lifecycle, 40);
    drop(authority.prepare_advance().unwrap());
    assert!(old.issue_capability(&old_intent, 20).is_ok());

    authority.prepare_advance().unwrap().commit().unwrap();
    assert!(matches!(
        old.issue_capability(&old_intent, 20),
        Err(ProcessContractError::CapabilityInvalid)
    ));
    assert!(matches!(
        old.approve(&old_intent, 20, true),
        Err(ProcessContractError::CapabilityInvalid)
    ));
    let new_lifecycle = lifecycle(30);
    let new_intent = intent(new_lifecycle.clone(), 41);
    let current = authority.bind_call(new_lifecycle).unwrap();
    let capability = current.issue_capability(&new_intent, 20).unwrap();
    let approval = current.approve(&new_intent, 20, true).unwrap();
    assert!(
        current
            .validate(new_intent, Some(&capability), Some(&approval), 10)
            .is_ok()
    );
}

#[test]
fn overflow_is_typed_and_leaves_authority_state_unchanged() {
    let authority = authority();
    authority.set_state_for_test(u64::MAX, 1, u64::MAX);
    assert!(matches!(
        authority.prepare_advance(),
        Err(ProcessContractError::CapabilityInvalid)
    ));
    let call = lifecycle(20);
    let boundary = authority.bind_call(call.clone()).unwrap();
    assert!(matches!(
        boundary.issue_capability(&intent(call, 40), 20),
        Err(ProcessContractError::CapabilityInvalid)
    ));
}

#[test]
fn authority_surface_hides_synchronization_and_debug_data() {
    let authority = include_str!("authority.rs");
    let boundary = include_str!("boundary.rs");

    for source in [authority, boundary] {
        assert!(!source.contains("pub state:"));
        assert!(!source.contains("pub replay_guard"));
        assert!(!source.contains("pub fn state"));
        assert!(!source.contains("pub fn replay_guard"));
    }
    assert!(!authority.contains("impl std::fmt::Debug for ProcessAuthorizationAuthorityV1"));
    assert!(!authority.contains("derive(Clone, Debug"));
}
