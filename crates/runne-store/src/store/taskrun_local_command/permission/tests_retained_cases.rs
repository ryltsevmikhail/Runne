//! Store/model ordering evidence, not native GO, controller scheduling or cancellation.
use super::{approval, ceremony, mode, support::Case};
use runne_application::{
    permission_modes::PermissionMode,
    ports::EventStoreError,
    project_trust::{ProjectTrustPersistence, ProjectTrustStatus},
};

#[test]
fn pending_compatible_capture_is_not_admission_or_spent() {
    let c = Case::new(false);
    ceremony::commit(&c.f, PermissionMode::RiskBased, 1);
    assert_eq!(
        c.f.store
            .local_command_permission_stop_reason(c.b.assignment(), &c.b)
            .unwrap(),
        None
    );
    let lease = c.lease();
    assert_eq!(c.burn(lease.as_ref()), Err(EventStoreError::CorruptData));
    assert_eq!(c.spent_on_owned_reopen(), 0);
}

#[test]
fn original_human_admission_after_compatible_reselection_keeps_original_proof() {
    let c = Case::new(false);
    let id = approval::confirm(&c.f, &c.b);
    ceremony::commit(&c.f, PermissionMode::RiskBased, 1);
    c.f.store
        .admit_local_command_permission(&c.b, Some(id))
        .unwrap();
    approval::durable(&c.f, &c.b, id);
    assert_eq!(
        c.f.store
            .observe_local_command_permission_policy(&c.b)
            .unwrap(),
        None
    );
}

#[test]
fn receipt_era_and_held_current_revision_are_independent() {
    let c = Case::new(true);
    let before = c.f.trust.load(c.f.trust_id()).unwrap();
    c.f.trust
        .commit(
            c.f.trust_id(),
            ProjectTrustStatus::Trusted,
            0,
            before.token(),
        )
        .unwrap();
    assert_ne!(c.f.trust.load(c.f.trust_id()).unwrap(), before);
    assert_eq!(
        c.f.store
            .observe_local_command_permission_policy(&c.b)
            .unwrap(),
        None
    );
    let lease = c.lease();
    c.burn(lease.as_ref()).unwrap();
    assert_eq!(c.release_model(lease.as_ref(), 0), (Ok(()), 1));
}

#[test]
fn current_trust_restriction_refuses_without_spent() {
    let c = Case::new(true);
    let before = c.f.trust.load(c.f.trust_id()).unwrap();
    c.f.trust
        .commit(
            c.f.trust_id(),
            ProjectTrustStatus::Untrusted,
            0,
            before.token(),
        )
        .unwrap();
    assert!(
        c.f.store
            .observe_local_command_permission_policy(&c.b)
            .unwrap()
            .is_some()
    );
    let lease = c.lease();
    assert_eq!(c.burn(lease.as_ref()), Err(EventStoreError::CorruptData));
    assert_eq!(c.spent_on_owned_reopen(), 0);
}

#[test]
fn independent_store_mode_first_before_outer_lease_refuses_burn() {
    let c = Case::new(true);
    // Separate real Store caller owns its own lease and completes BEFORE this outer lease.
    // This is not execution of the protected controller process.
    {
        let independent_lease = c.lease();
        mode::commit_expiring(
            &c.f,
            PermissionMode::AskAlways,
            1,
            independent_lease.as_ref(),
        );
    }
    let lease = c.lease();
    assert_eq!(c.burn(lease.as_ref()), Err(EventStoreError::CorruptData));
    assert_eq!(c.spent_on_owned_reopen(), 0);
}

#[test]
fn incompatible_same_borrowed_lease_gap_refuses_model_callback() {
    let c = Case::new(true);
    let lease = c.lease();
    c.burn(lease.as_ref()).unwrap();
    mode::commit_expiring(&c.f, PermissionMode::AskAlways, 1, lease.as_ref());
    assert_eq!(
        c.release_model(lease.as_ref(), 0),
        (Err(EventStoreError::CorruptData), 0)
    );
    assert_eq!(c.spent_on_owned_reopen(), 1);
}

#[test]
fn model_counter_first_then_mode_stop_preserves_spent_on_reopen() {
    let c = Case::new(true);
    let lease = c.lease();
    c.burn(lease.as_ref()).unwrap();
    assert_eq!(c.release_model(lease.as_ref(), 0), (Ok(()), 1));
    mode::commit_expiring(&c.f, PermissionMode::AskAlways, 1, lease.as_ref());
    assert_eq!(
        c.f.store
            .local_command_permission_stop_reason(c.b.assignment(), &c.b)
            .unwrap(),
        Some(2)
    );
    assert_eq!(c.spent_on_owned_reopen(), 1);
    // No second private release invocation is used as a fake public replay check.
    assert_eq!(c.burn(lease.as_ref()), Err(EventStoreError::CorruptData));
}

#[test]
fn postcallback_running_cas_failure_preserves_committed_burn() {
    let c = Case::new(true);
    let lease = c.lease();
    c.burn(lease.as_ref()).unwrap();
    assert_eq!(
        c.release_model(lease.as_ref(), 1),
        (Err(EventStoreError::CorruptData), 1)
    );
    assert_eq!(c.spent_on_owned_reopen(), 1);
    assert_eq!(c.burn(lease.as_ref()), Err(EventStoreError::CorruptData));
}

#[test]
fn postcallback_commit_failure_preserves_spent_and_requires_recovery() {
    let c = Case::new(true);
    let lease = c.lease();
    c.burn(lease.as_ref()).unwrap();
    assert_eq!(
        c.release_model(lease.as_ref(), 2),
        (Err(EventStoreError::Unavailable), 1)
    );
    assert_eq!(c.spent_on_owned_reopen(), 1);
    assert_eq!(c.burn(lease.as_ref()), Err(EventStoreError::CorruptData));
}

#[test]
fn uncertain_stop_never_authorizes_model_release() {
    let c = Case::new(true);
    let lease = c.lease();
    c.burn(lease.as_ref()).unwrap();
    assert_eq!(
        c.f.store
            .record_local_command_permission_stop(c.b.assignment(), &c.b, 6)
            .unwrap(),
        6
    );
    assert_eq!(
        c.release_model(lease.as_ref(), 0),
        (Err(EventStoreError::CorruptData), 0)
    );
    assert_eq!(c.spent_on_owned_reopen(), 1);
}

#[test]
fn duplicate_actual_burn_is_not_new_eligibility_after_reopen() {
    let c = Case::new(true);
    let lease = c.lease();
    c.burn(lease.as_ref()).unwrap();
    assert_eq!(c.spent_on_owned_reopen(), 1);
    assert_eq!(c.burn(lease.as_ref()), Err(EventStoreError::CorruptData));
    assert_eq!(c.spent_on_owned_reopen(), 1);
}
