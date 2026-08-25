use super::super::{
    CredentialBindingDigest, CredentialEnrollmentAuthorityPair, CredentialEnrollmentError,
    CredentialFence, CredentialLifecycleRevision, CredentialOperationId, CredentialProcessBinding,
    CredentialReleaseMigrationBinding, CredentialTicketAttempt, RawCredentialTicket,
    WriterIdentityMigrationPhase,
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
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let base = migration_with(&measurements, 42, 1, 1, 1, 1, 1, [30, 31, 32, 33]);
    let counterpart = migration_with(&measurements, 42, 2, 2, 1, 1, 1, [30, 31, 32, 33]);
    assert!(base.validates_counterpart(&counterpart).is_ok());
    for invalid in [
        migration_with(&measurements, 42, 1, 2, 1, 1, 1, [30, 31, 32, 33]),
        migration_with(&measurements, 42, 2, 1, 1, 1, 1, [30, 31, 32, 33]),
    ] {
        assert_eq!(
            base.validates_counterpart(&invalid),
            Err(CredentialEnrollmentError::InvalidInput)
        );
    }
    assert_ne!(base.digest(), counterpart.digest());
}

#[test]
fn credential_enrollment_release_migration_rejects_snapshot_mismatches() {
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let base = migration_with(&measurements, 42, 1, 1, 1, 1, 1, [30, 31, 32, 33]);
    for counterpart in [
        migration_with(&measurements, 42, 2, 2, 1, 1, 1, [34, 31, 32, 33]),
        migration_with(&measurements, 42, 2, 2, 1, 1, 1, [30, 34, 32, 33]),
        migration_with(&measurements, 42, 2, 2, 1, 1, 1, [30, 31, 34, 33]),
        migration_with(&measurements, 42, 2, 2, 2, 1, 1, [30, 31, 32, 33]),
        migration_with(&measurements, 42, 2, 2, 1, 2, 1, [30, 31, 32, 33]),
        migration_with(&measurements, 42, 2, 2, 1, 1, 2, [30, 31, 32, 33]),
        migration_with(&measurements, 42, 2, 2, 1, 1, 1, [30, 31, 32, 34]),
        migration_with(&measurements, 43, 2, 2, 1, 1, 1, [30, 31, 32, 33]),
    ] {
        assert_eq!(
            base.validates_counterpart(&counterpart),
            Err(CredentialEnrollmentError::InvalidInput)
        );
    }
}

#[test]
fn credential_enrollment_release_migration_rejects_foreign_authority_pair_evidence() {
    let (base, _) = migration_pair();
    let foreign = migration(42, 2, 2, 1, 1, 1, [30, 31, 32, 33]);
    assert_eq!(
        base.validates_counterpart(&foreign),
        Err(CredentialEnrollmentError::InvalidEvidence)
    );
}

#[test]
fn credential_enrollment_release_migration_classifies_structural_invalidity_as_input() {
    assert_eq!(
        migration_result(42, 1, 1, 0, 1, 1, [30, 31, 32, 33]),
        Err(CredentialEnrollmentError::InvalidInput)
    );
    assert_eq!(
        migration_result(42, 1, 1, 1, 1, 1, [30, 30, 32, 32]),
        Err(CredentialEnrollmentError::InvalidInput)
    );
}

#[test]
fn credential_enrollment_release_migration_tuple_digests_commit_their_exact_components() {
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let base = migration_with(&measurements, 42, 1, 1, 1, 1, 1, [30, 31, 32, 33]);
    for (changed, changes_old) in [
        (
            migration_with(&measurements, 42, 1, 1, 1, 1, 1, [34, 31, 32, 33]),
            true,
        ),
        (
            migration_with(&measurements, 42, 1, 1, 1, 1, 1, [30, 34, 32, 33]),
            false,
        ),
        (
            migration_with(&measurements, 42, 1, 1, 1, 1, 1, [30, 31, 34, 33]),
            true,
        ),
        (
            migration_with(&measurements, 42, 1, 1, 1, 1, 1, [30, 31, 32, 34]),
            false,
        ),
    ] {
        assert_eq!(
            base.old_tuple_digest() != changed.old_tuple_digest(),
            changes_old
        );
        assert_eq!(
            base.new_tuple_digest() != changed.new_tuple_digest(),
            !changes_old
        );
    }
}

fn migration_pair() -> (
    CredentialReleaseMigrationBinding,
    CredentialReleaseMigrationBinding,
) {
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let base = migration_with(&measurements, 42, 1, 1, 1, 1, 1, [30, 31, 32, 33]);
    let counterpart = migration_with(&measurements, 42, 2, 2, 1, 1, 1, [30, 31, 32, 33]);
    (base, counterpart)
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
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    migration_with(
        &measurements,
        id,
        phase,
        process_seed,
        generation,
        revision,
        fence,
        tuples,
    )
}

#[allow(clippy::too_many_arguments)]
fn migration_with(
    measurements: &super::super::CredentialEnrollmentMeasurementAuthority,
    id: u8,
    phase: u8,
    process_seed: u8,
    generation: u64,
    revision: u64,
    fence: u64,
    tuples: [u8; 4],
) -> CredentialReleaseMigrationBinding {
    migration_result_with(
        measurements,
        id,
        phase,
        process_seed,
        generation,
        revision,
        fence,
        tuples,
    )
    .unwrap()
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
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    migration_result_with(
        &measurements,
        id,
        phase,
        process_seed,
        generation,
        revision,
        fence,
        tuples,
    )
}

#[allow(clippy::too_many_arguments)]
fn migration_result_with(
    measurements: &super::super::CredentialEnrollmentMeasurementAuthority,
    id: u8,
    phase: u8,
    process_seed: u8,
    generation: u64,
    revision: u64,
    fence: u64,
    tuples: [u8; 4],
) -> Result<CredentialReleaseMigrationBinding, CredentialEnrollmentError> {
    measurements.issue_credential_release_migration_binding(
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
        process(measurements, process_seed),
    )
}

fn process(
    measurements: &super::super::CredentialEnrollmentMeasurementAuthority,
    seed: u8,
) -> CredentialProcessBinding {
    CredentialProcessBinding::new(
        measurements
            .writer_process_start_identity([seed; 32])
            .unwrap(),
        measurements
            .writer_process_handle_identity([seed + 10; 32])
            .unwrap(),
    )
}

fn measured(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}
