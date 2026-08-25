use super::super::{
    BeginCredentialVerification, CredentialBindingDigest, CredentialEnrollmentAuthorityPair,
    CredentialEnrollmentError, CredentialFence, CredentialLifecycleRevision, CredentialOperationId,
    CredentialVerificationKind, CredentialVerifierRevision, WriterIdentityMigrationPhase,
};
use crate::ProviderId;

#[test]
fn credential_verification_capability_rejects_cross_pair_substitution() {
    let (store, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let (foreign_store, foreign_measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let capability = measurements
        .issue_credential_verification_capability(
            store.issue_credential_verification_lease(begin(1)),
            digest(2),
        )
        .unwrap();
    assert!(
        store
            .validate_credential_verification_capability(&capability)
            .is_ok()
    );
    assert!(
        foreign_store
            .validate_credential_verification_capability(&capability)
            .is_err()
    );
    assert!(
        measurements
            .issue_credential_verification_capability(
                foreign_store.issue_credential_verification_lease(begin(3)),
                digest(4),
            )
            .is_err()
    );
    let foreign_capability = foreign_measurements
        .issue_credential_verification_capability(
            foreign_store.issue_credential_verification_lease(begin(5)),
            digest(6),
        )
        .unwrap();
    assert!(
        store
            .validate_credential_verification_capability(&foreign_capability)
            .is_err()
    );
}

#[test]
fn credential_migration_authorities_reject_cross_pair_process_and_binding_evidence() {
    let (store, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let (foreign_store, foreign_measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let binding = measurements
        .issue_credential_release_migration_binding(
            CredentialOperationId::from_bytes([7; 16]).unwrap(),
            WriterIdentityMigrationPhase::OldWriterEffect,
            digest(8),
            digest(9),
            digest(10),
            digest(11),
            1,
            CredentialLifecycleRevision::new(1).unwrap(),
            CredentialFence::new(1).unwrap(),
            process(&measurements, 12),
        )
        .unwrap();
    let metadata = store.issue_credential_migration_metadata(&binding).unwrap();
    assert_eq!(metadata.old_tuple_digest(), binding.old_tuple_digest());
    assert_eq!(metadata.new_tuple_digest(), binding.new_tuple_digest());
    assert!(
        store
            .validate_credential_migration_metadata(&metadata)
            .is_ok()
    );
    assert!(
        foreign_store
            .validate_credential_migration_metadata(&metadata)
            .is_err()
    );
    assert_eq!(
        foreign_store.issue_credential_migration_metadata(&binding),
        Err(CredentialEnrollmentError::InvalidEvidence)
    );
    assert_eq!(
        measurements.issue_credential_release_migration_binding(
            CredentialOperationId::from_bytes([15; 16]).unwrap(),
            WriterIdentityMigrationPhase::NewWriterVerify,
            digest(16),
            digest(17),
            digest(18),
            digest(19),
            1,
            CredentialLifecycleRevision::new(1).unwrap(),
            CredentialFence::new(1).unwrap(),
            process(&foreign_measurements, 20),
        ),
        Err(CredentialEnrollmentError::InvalidEvidence)
    );
}

#[test]
fn credential_migration_metadata_restart_hydration_remains_store_authority_bound() {
    let (store, _) = CredentialEnrollmentAuthorityPair::new().split();
    let (foreign_store, _) = CredentialEnrollmentAuthorityPair::new().split();
    let migration_id = CredentialOperationId::from_bytes([21; 16]).unwrap();
    let metadata = store.hydrate_persisted_credential_migration_metadata(
        migration_id,
        WriterIdentityMigrationPhase::NewWriterVerify,
        digest(22),
        digest(23),
    );
    assert_eq!(metadata.migration_id(), migration_id);
    assert_eq!(
        metadata.phase(),
        WriterIdentityMigrationPhase::NewWriterVerify
    );
    assert_eq!(metadata.old_tuple_digest(), digest(22));
    assert_eq!(metadata.new_tuple_digest(), digest(23));
    assert!(
        store
            .validate_credential_migration_metadata(&metadata)
            .is_ok()
    );
    assert!(
        foreign_store
            .validate_credential_migration_metadata(&metadata)
            .is_err()
    );
}

fn begin(value: u8) -> BeginCredentialVerification {
    BeginCredentialVerification::new(
        CredentialOperationId::from_bytes([value; 16]).unwrap(),
        None,
        ProviderId::new("openai").unwrap(),
        CredentialVerificationKind::Local,
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        digest(value + 20),
        CredentialVerifierRevision::new(1).unwrap(),
        1,
        2,
    )
    .unwrap()
}

fn process(
    measurements: &super::super::CredentialEnrollmentMeasurementAuthority,
    value: u8,
) -> super::super::CredentialProcessBinding {
    super::super::CredentialProcessBinding::new(
        measurements
            .writer_process_start_identity([value; 32])
            .unwrap(),
        measurements
            .writer_process_handle_identity([value + 1; 32])
            .unwrap(),
    )
}

fn digest(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}
