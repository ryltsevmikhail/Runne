use super::{
    CredentialBindingDigest, CredentialClaimBinding, CredentialFence, CredentialLifecycleRevision,
    CredentialOperationAction as Action, CredentialOperationId, CredentialOperationState as State,
    CredentialProcessBinding, CredentialReleaseMigrationBinding, CredentialTicketAttempt,
    CredentialTransitionEvidence as Evidence, RawCredentialTicket, TransitionCommand,
    WriterIdentityMigrationPhase, allows_structural_transition,
};
use crate::{CredentialVersionRef, ProviderId};

#[test]
fn credential_enrollment_transition_allows_only_the_closed_structural_graph() {
    let allowed = [
        (State::Prepared, State::Claimed),
        (State::Prepared, State::Failed),
        (State::Prepared, State::Expired),
        (State::Prepared, State::Cancelled),
        (State::Claimed, State::NativeEffectObserved),
        (State::Claimed, State::Failed),
        (State::NativeEffectObserved, State::ReadbackVerified),
        (State::NativeEffectObserved, State::Failed),
        (State::ReadbackVerified, State::Completed),
        (State::Completed, State::Tombstoned),
        (State::Failed, State::Tombstoned),
        (State::Expired, State::Tombstoned),
        (State::Cancelled, State::Tombstoned),
    ];
    for from in State::ALL {
        for to in State::ALL {
            assert_eq!(
                allows_structural_transition(from, to),
                allowed.contains(&(from, to)),
                "unexpected structural edge {from:?} -> {to:?}",
            );
        }
    }

    assert_eq!(Action::Pair as u8, 1);
}

#[test]
fn credential_enrollment_transition_requires_exact_post_claim_evidence() {
    let digest = CredentialBindingDigest::from_measured([7; 32]).unwrap();
    let fence = CredentialFence::new(3).unwrap();
    assert!(
        TransitionCommand::new(
            Action::Pair,
            State::Claimed,
            State::Failed,
            Evidence::ExactAbsenceReadback(digest),
        )
        .is_ok()
    );
    assert!(
        TransitionCommand::new(Action::Pair, State::Claimed, State::Failed, Evidence::None,)
            .is_err()
    );
    assert!(
        TransitionCommand::new(
            Action::Revoke,
            State::Claimed,
            State::Failed,
            Evidence::ExactAbsenceReadback(digest),
        )
        .is_err()
    );
    assert!(
        TransitionCommand::new(
            Action::Revoke,
            State::Claimed,
            State::NativeEffectObserved,
            Evidence::RevokeFenceCommitted(fence),
        )
        .is_ok()
    );
    assert!(
        TransitionCommand::new(
            Action::Pair,
            State::ReadbackVerified,
            State::Completed,
            Evidence::ExactVersionReadback(digest),
        )
        .is_ok()
    );
}

#[test]
fn credential_enrollment_identity_rejects_zero_monotonic_values_and_raw_ticket() {
    assert!(CredentialLifecycleRevision::new(0).is_err());
    assert!(CredentialFence::new(0).is_err());
    assert!(CredentialTicketAttempt::new(0).is_err());
    assert!(CredentialOperationId::from_bytes([0; 16]).is_err());
    assert!(CredentialBindingDigest::from_measured([0; 32]).is_err());
    assert!(RawCredentialTicket::from_os_random([0; 32]).is_err());
    assert!(RawCredentialTicket::from_entropy(Err(())).is_err());
}

#[test]
fn credential_enrollment_claim_binding_changes_for_each_measured_dimension() {
    let binding = claim_binding();
    let digest = binding.digest();
    macro_rules! changed {
        ($field:ident, $value:expr) => {{
            let mut candidate = binding.clone();
            candidate.$field = $value;
            assert_ne!(candidate.digest(), digest, stringify!($field));
        }};
    }
    changed!(candidate_source_identity, measured(2));
    changed!(release_manifest_digest, measured(3));
    changed!(desktop_executable_identity, measured(4));
    changed!(writer_executable_identity, measured(5));
    changed!(reader_executable_identity, measured(6));
    changed!(contract_bundle_digest, measured(7));
    changed!(daemon_authority_id, measured(8));
    changed!(protected_session_id, measured(9));
    changed!(writer_launch_id, measured(10));
    changed!(writer_process_start_identity, measured(11));
    changed!(writer_process_handle_identity, measured(12));
    changed!(broker_channel_binding, measured(13));
    changed!(continuation_binding_digest, measured(14));
    changed!(ticket_digest, measured(16));
    changed!(database_generation, 2);
    changed!(desktop_supervisor_generation, 3);
    changed!(
        operation_id,
        CredentialOperationId::from_bytes([16; 16]).unwrap()
    );
    changed!(ticket_attempt, CredentialTicketAttempt::new(2).unwrap());
    changed!(provider_id, ProviderId::new("anthropic").unwrap());
    changed!(action, Action::Revoke);
    changed!(
        credential_version,
        CredentialVersionRef::new(ProviderId::new("anthropic").unwrap(), 2).unwrap()
    );
    changed!(
        expected_lifecycle_revision,
        CredentialLifecycleRevision::new(2).unwrap()
    );
    changed!(expected_prior_fence, CredentialFence::new(2).unwrap());
    changed!(issued_at_high_water, 2);
    changed!(expires_at_high_water, 3);
}

#[test]
fn credential_enrollment_release_migration_requires_distinct_phase_processes() {
    let migration_id = CredentialOperationId::from_bytes([20; 16]).unwrap();
    let base = migration(
        migration_id,
        WriterIdentityMigrationPhase::OldWriterEffect,
        process(21),
    );
    let counterpart = migration(
        migration_id,
        WriterIdentityMigrationPhase::NewWriterVerify,
        process(22),
    );
    assert!(base.validates_counterpart(&counterpart).is_ok());
    let same_process = migration(
        migration_id,
        WriterIdentityMigrationPhase::NewWriterVerify,
        process(21),
    );
    assert!(base.validates_counterpart(&same_process).is_err());
    assert_ne!(base.digest(), counterpart.digest());
}

fn measured(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}
fn process(value: u8) -> CredentialProcessBinding {
    CredentialProcessBinding::new(measured(value), measured(value + 1))
}
fn claim_binding() -> CredentialClaimBinding {
    CredentialClaimBinding {
        candidate_source_identity: measured(1),
        release_manifest_digest: measured(2),
        desktop_executable_identity: measured(3),
        writer_executable_identity: measured(4),
        reader_executable_identity: measured(5),
        contract_bundle_digest: measured(6),
        daemon_authority_id: measured(7),
        database_generation: 1,
        protected_session_id: measured(8),
        desktop_supervisor_generation: 1,
        writer_launch_id: measured(9),
        writer_process_start_identity: measured(10),
        writer_process_handle_identity: measured(11),
        broker_channel_binding: measured(12),
        continuation_binding_digest: measured(13),
        operation_id: CredentialOperationId::from_bytes([14; 16]).unwrap(),
        ticket_attempt: CredentialTicketAttempt::new(1).unwrap(),
        ticket_digest: measured(15),
        provider_id: ProviderId::new("openai").unwrap(),
        action: Action::Pair,
        credential_version: CredentialVersionRef::new(ProviderId::new("openai").unwrap(), 1)
            .unwrap(),
        expected_lifecycle_revision: CredentialLifecycleRevision::new(1).unwrap(),
        expected_prior_fence: CredentialFence::new(1).unwrap(),
        issued_at_high_water: 1,
        expires_at_high_water: 2,
    }
}
fn migration(
    migration_id: CredentialOperationId,
    phase: WriterIdentityMigrationPhase,
    live_process: CredentialProcessBinding,
) -> CredentialReleaseMigrationBinding {
    CredentialReleaseMigrationBinding {
        migration_id,
        phase,
        old_candidate_and_manifest: measured(30),
        new_candidate_and_manifest: measured(31),
        old_desktop_writer_reader_contract: measured(32),
        new_desktop_writer_reader_contract: measured(33),
        database_generation: 1,
        expected_lifecycle_revision: CredentialLifecycleRevision::new(1).unwrap(),
        expected_prior_fence: CredentialFence::new(1).unwrap(),
        live_process,
    }
}

#[test]
fn credential_enrollment_transition_rejects_shortcuts_and_post_claim_closure() {
    for transition in [
        (State::Claimed, State::Completed),
        (State::Claimed, State::Expired),
        (State::Claimed, State::Cancelled),
        (State::NativeEffectObserved, State::Expired),
        (State::NativeEffectObserved, State::Cancelled),
        (State::Completed, State::Failed),
        (State::Tombstoned, State::Prepared),
    ] {
        assert!(!allows_structural_transition(transition.0, transition.1));
    }
}
