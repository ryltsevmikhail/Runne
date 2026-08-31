use crate::{
    BeginCredentialOperation, CredentialBindingDigest, CredentialEnrollmentError, CredentialFence,
    CredentialInstallationOwnerId, CredentialLifecycleRevision, CredentialOperationAction,
    CredentialOperationId, CredentialVersionRef, ProviderId,
};
use runne_domain::id::{CommandId, IdempotencyKey};

fn begin(expiry: u64) -> Result<BeginCredentialOperation, CredentialEnrollmentError> {
    let provider = ProviderId::new("openai").unwrap();
    BeginCredentialOperation::new(
        CommandId::from_bytes([1; 16]),
        IdempotencyKey::new("expiry").unwrap(),
        CredentialOperationId::from_bytes([2; 16]).unwrap(),
        CredentialInstallationOwnerId::from_bytes([3; 32]).unwrap(),
        provider.clone(),
        CredentialOperationAction::Pair,
        Some(CredentialVersionRef::new(provider, 1).unwrap()),
        None,
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        CredentialBindingDigest::from_measured([4; 32]).unwrap(),
        expiry,
    )
}

#[test]
fn begin_credential_operation_rejects_zero_expiry_at_construction() {
    assert_eq!(
        begin(0).unwrap_err(),
        CredentialEnrollmentError::InvalidInput
    );
}

#[test]
fn begin_credential_operation_rejects_expiry_outside_durable_i64_range() {
    assert_eq!(
        begin(i64::MAX as u64 + 1).unwrap_err(),
        CredentialEnrollmentError::InvalidInput
    );
}

#[test]
fn begin_credential_operation_exposes_only_a_positive_durable_expiry() {
    assert_eq!(begin(1).unwrap().begin_proof_expires_at_high_water(), 1);
}
