use super::*;
use crate::{CredentialEnrollmentAuthorityPair, CredentialEnrollmentError};

fn fixture() -> (
    crate::CredentialEnrollmentStoreAuthority,
    crate::CredentialEnrollmentMeasurementAuthority,
    CredentialCleanupRecoveryRequest,
) {
    let (store, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let request = CredentialCleanupRecoveryRequest::new(
        CredentialOperationId::from_bytes([1; 16]).unwrap(),
        CredentialInstallationOwnerId::from_bytes([2; 32]).unwrap(),
        measurements.release_manifest_digest([3; 32]).unwrap(),
        measurements.protected_session_id([4; 32]).unwrap(),
        measurements.desktop_supervisor_generation(1).unwrap(),
        1,
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        measurements.continuation_binding_digest([5; 32]).unwrap(),
        30,
    );
    (store, measurements, request)
}

#[test]
fn recovery_request_rejects_mixed_authority_measurements() {
    let (store, _, valid) = fixture();
    assert!(store.validate_cleanup_recovery_request(&valid).is_ok());
    let (_, other) = CredentialEnrollmentAuthorityPair::new().split();
    let mut changed = valid.clone();
    changed.session = other.protected_session_id([4; 32]).unwrap();
    assert_eq!(
        store.validate_cleanup_recovery_request(&changed),
        Err(CredentialEnrollmentError::InvalidEvidence)
    );
    let mut changed = valid;
    changed.release = other.release_manifest_digest([3; 32]).unwrap();
    assert_eq!(
        store.validate_cleanup_recovery_request(&changed),
        Err(CredentialEnrollmentError::InvalidEvidence)
    );
}

#[test]
fn recovery_request_rejects_unbounded_duration_generation_and_aliased_proof() {
    let (store, measurements, valid) = fixture();
    for duration in [0, 301, u64::MAX] {
        let mut changed = valid.clone();
        changed.ttl_seconds = duration;
        assert_eq!(
            store.validate_cleanup_recovery_request(&changed),
            Err(CredentialEnrollmentError::InvalidInput)
        );
    }
    for generation in [0, u64::MAX] {
        let mut changed = valid.clone();
        changed.database_generation = generation;
        assert_eq!(
            store.validate_cleanup_recovery_request(&changed),
            Err(CredentialEnrollmentError::InvalidInput)
        );
    }
    let mut changed = valid;
    changed.continuation = measurements.continuation_binding_digest([4; 32]).unwrap();
    assert_eq!(
        store.validate_cleanup_recovery_request(&changed),
        Err(CredentialEnrollmentError::InvalidInput)
    );
}
