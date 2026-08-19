use std::thread;

use super::ProcessContractError;
use super::authority_tests::{authority, intent, lifecycle};

fn boundary() -> (
    super::ProcessAuthorizationAuthorityV1,
    super::ProcessAuthorizationBoundaryV1,
    super::ProcessIntentV1,
) {
    let authority = authority();
    let call = lifecycle(20);
    let intent = intent(call.clone(), 40);
    let boundary = authority.bind_call(call).unwrap();
    (authority, boundary, intent)
}

fn authorized(
    boundary: &super::ProcessAuthorizationBoundaryV1,
    intent: &super::ProcessIntentV1,
) -> (super::ProcessCapabilityV1, super::ProcessApprovalV1) {
    (
        boundary.issue_capability(intent, 20).unwrap(),
        boundary.approve(intent, 20, true).unwrap(),
    )
}

#[test]
fn same_seed_authorities_have_unique_ids_and_reject_foreign_authorization() {
    let (_, first, intent) = boundary();
    let (_, second, _) = boundary();
    let (capability, approval) = authorized(&first, &intent);

    assert_ne!(
        capability.id_label(),
        second.issue_capability(&intent, 20).unwrap().id_label()
    );
    assert!(matches!(
        second.validate(intent.clone(), Some(&capability), Some(&approval), 10),
        Err(ProcessContractError::CapabilityInvalid)
    ));
    assert!(
        first
            .validate(intent, Some(&capability), Some(&approval), 10)
            .is_ok()
    );
}

#[test]
fn local_capability_with_foreign_approval_is_approval_invalid() {
    let (_, first, intent) = boundary();
    let (_, second, _) = boundary();
    let capability = second.issue_capability(&intent, 20).unwrap();
    let approval = first.approve(&intent, 20, true).unwrap();

    assert!(matches!(
        second.validate(intent, Some(&capability), Some(&approval), 10),
        Err(ProcessContractError::ApprovalInvalid)
    ));
}

#[test]
fn cloned_authority_children_share_one_replay_domain() {
    let authority = authority();
    let call = lifecycle(20);
    let intent = intent(call.clone(), 40);
    let first = authority.bind_call(call.clone()).unwrap();
    let second = authority.clone().bind_call(call).unwrap();
    let (capability, approval) = authorized(&first, &intent);

    assert!(
        second
            .validate(intent.clone(), Some(&capability), Some(&approval), 10)
            .is_ok()
    );
    assert!(matches!(
        first.validate(intent, Some(&capability), Some(&approval), 10),
        Err(ProcessContractError::CapabilityInvalid)
    ));
}

#[test]
fn concurrent_same_seed_authorities_have_unique_ids_and_cross_reject() {
    let workers: Vec<_> = (0..8)
        .map(|_| {
            thread::spawn(|| {
                let (_, boundary, intent) = boundary();
                boundary.issue_capability(&intent, 20).unwrap().id_label()
            })
        })
        .collect();
    let mut ids: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 8);

    let (_, first, intent) = boundary();
    let (_, second, _) = boundary();
    let (capability, approval) = authorized(&first, &intent);
    assert!(matches!(
        second.validate(intent, Some(&capability), Some(&approval), 10),
        Err(ProcessContractError::CapabilityInvalid)
    ));
}

#[test]
fn local_allocator_reaches_max_without_wrapping() {
    let (authority, boundary, intent) = boundary();
    authority.set_state_for_test(1, 1, u64::MAX - 1);

    let final_capability = boundary.issue_capability(&intent, 20).unwrap();
    assert_eq!(&final_capability.id_label()[8..], &u64::MAX.to_be_bytes());
    assert!(matches!(
        boundary.issue_capability(&intent, 20),
        Err(ProcessContractError::CapabilityInvalid)
    ));
}

#[test]
fn overflow_failures_leave_capability_revision_and_epoch_unchanged() {
    let (authority, boundary, intent) = boundary();
    authority.set_state_for_test(1, 1, u64::MAX);
    assert!(boundary.issue_capability(&intent, 20).is_err());
    assert_eq!(authority.state_for_test(), (1, 1, u64::MAX));
    assert!(boundary.issue_capability(&intent, 20).is_err());
    assert_eq!(authority.state_for_test(), (1, 1, u64::MAX));

    authority.set_state_for_test(u64::MAX, 1, 0);
    assert!(authority.prepare_advance().is_err());
    assert_eq!(authority.state_for_test(), (u64::MAX, 1, 0));
    authority.set_state_for_test(1, u64::MAX, 0);
    assert!(authority.prepare_advance().is_err());
    assert_eq!(authority.state_for_test(), (1, u64::MAX, 0));
}

#[test]
fn advance_rejects_stale_validate_and_current_boundaries_consume_once() {
    let (authority, first, stale_intent) = boundary();
    let (capability, approval) = authorized(&first, &stale_intent);
    authority.prepare_advance().unwrap().commit().unwrap();
    assert!(matches!(
        first.validate(stale_intent, Some(&capability), Some(&approval), 10),
        Err(ProcessContractError::CapabilityInvalid)
    ));

    let first = authority.bind_call(lifecycle(20)).unwrap();
    let second = authority.bind_call(lifecycle(20)).unwrap();
    let intent = intent(lifecycle(20), 40);
    let (capability, approval) = authorized(&first, &intent);
    let successes = [first, second]
        .into_iter()
        .filter(|boundary| {
            boundary
                .validate(intent.clone(), Some(&capability), Some(&approval), 10)
                .is_ok()
        })
        .count();
    assert_eq!(successes, 1);
}

#[test]
fn authority_domain_and_errors_are_redacted() {
    let source = include_str!("authorization.rs");
    assert!(source.contains("struct AuthorizationReplayDomainV1"));
    assert!(!source.contains("derive(Debug"));
    assert!(!source.contains("pub(crate) legacy_seed"));
    assert!(!source.contains("pub(crate) authority_instance"));
    assert_eq!(
        ProcessContractError::CapabilityInvalid.to_string(),
        "process capability is invalid"
    );
}
