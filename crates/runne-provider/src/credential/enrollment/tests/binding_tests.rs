use super::super::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationId, CredentialProcessBinding,
    CredentialReleaseMigrationBinding, CredentialTicketAttempt, RawCredentialTicket,
    WriterIdentityMigrationPhase, WriterProcessHandleIdentity, WriterProcessStartIdentity,
};

#[test]
fn credential_enrollment_identity_rejects_zero_monotonic_values_and_raw_ticket() {
    assert!(CredentialLifecycleRevision::new(0).is_err());
    assert!(CredentialFence::new(0).is_err());
    assert!(CredentialTicketAttempt::new(0).is_err());
    assert!(CredentialOperationId::from_bytes([0; 16]).is_err());
    assert!(CredentialBindingDigest::from_measured([0; 32]).is_err());
    assert!(RawCredentialTicket::generate().is_ok());
}

#[test]
fn credential_enrollment_release_migration_requires_distinct_phase_processes() {
    let (base, counterpart) = migration_pair();
    assert!(base.validates_counterpart(&counterpart).is_ok());
    assert!(
        base.validates_counterpart(&migration(42, 1, 2, 1, 1, 1, [30, 31, 32, 33]))
            .is_err()
    );
    assert!(
        base.validates_counterpart(&migration(42, 2, 1, 1, 1, 1, [30, 31, 32, 33]))
            .is_err()
    );
    assert_ne!(base.digest(), counterpart.digest());
}

#[test]
fn credential_enrollment_release_migration_rejects_snapshot_mismatches() {
    let (base, _) = migration_pair();
    for counterpart in [
        migration(42, 2, 2, 2, 1, 1, [30, 31, 32, 33]),
        migration(42, 2, 2, 1, 2, 1, [30, 31, 32, 33]),
        migration(42, 2, 2, 1, 1, 2, [30, 31, 32, 33]),
        migration(42, 2, 2, 1, 1, 1, [30, 31, 32, 34]),
        migration(43, 2, 2, 1, 1, 1, [30, 31, 32, 33]),
    ] {
        assert!(base.validates_counterpart(&counterpart).is_err());
    }
}

#[test]
fn credential_enrollment_release_migration_rejects_same_release_tuple() {
    assert!(migration_result(42, 1, 1, 1, 1, 1, [30, 30, 32, 32]).is_err());
}

fn migration_pair() -> (
    CredentialReleaseMigrationBinding,
    CredentialReleaseMigrationBinding,
) {
    (
        migration(42, 1, 1, 1, 1, 1, [30, 31, 32, 33]),
        migration(42, 2, 2, 1, 1, 1, [30, 31, 32, 33]),
    )
}

fn migration(
    id: u8,
    phase: u8,
    process_seed: u8,
    generation: u64,
    revision: u64,
    fence: u64,
    tuples: [u8; 4],
) -> CredentialReleaseMigrationBinding {
    migration_result(id, phase, process_seed, generation, revision, fence, tuples).unwrap()
}

fn migration_result(
    id: u8,
    phase: u8,
    process_seed: u8,
    generation: u64,
    revision: u64,
    fence: u64,
    tuples: [u8; 4],
) -> Result<CredentialReleaseMigrationBinding, CredentialEnrollmentError> {
    CredentialReleaseMigrationBinding::new(
        CredentialOperationId::from_bytes([id; 16]).unwrap(),
        if phase == 1 {
            WriterIdentityMigrationPhase::OldWriterEffect
        } else {
            WriterIdentityMigrationPhase::NewWriterVerify
        },
        measured(tuples[0]),
        measured(tuples[1]),
        measured(tuples[2]),
        measured(tuples[3]),
        generation,
        CredentialLifecycleRevision::new(revision).unwrap(),
        CredentialFence::new(fence).unwrap(),
        process(process_seed),
    )
}

fn process(seed: u8) -> CredentialProcessBinding {
    CredentialProcessBinding::new(
        WriterProcessStartIdentity::from_measured([seed; 32]).unwrap(),
        WriterProcessHandleIdentity::from_measured([seed + 10; 32]).unwrap(),
    )
}

fn measured(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}
