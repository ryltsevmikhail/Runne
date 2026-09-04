use super::super::{AcceptedCredentialCleanupRecovery, CredentialCleanupRecoveryRequest};
use super::{CredentialEnrollmentError, CredentialEnrollmentStoreAuthority};

impl super::CredentialEnrollmentMeasurementAuthority {
    /// Checks the store witness's issuer before protected endpoint handoff.
    pub fn validate_cleanup_recovery(
        &self,
        accepted: &AcceptedCredentialCleanupRecovery,
    ) -> Result<(), CredentialEnrollmentError> {
        if accepted.belongs_to(&self.seal) {
            Ok(())
        } else {
            Err(CredentialEnrollmentError::InvalidEvidence)
        }
    }

    /// Requires the recovery witness and live measurements to share issuer and context.
    pub fn validate_cleanup_recovery_measurements(
        &self,
        accepted: &AcceptedCredentialCleanupRecovery,
        measurements: &super::CredentialMeasurementSnapshot,
        database: u64,
        supervisor: u64,
    ) -> Result<(), CredentialEnrollmentError> {
        if !accepted.belongs_to(&self.seal)
            || !measurements.belongs_to(&self.seal)
            || !measurements.matches_cleanup_recovery(accepted.request(), database, supervisor)
        {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        Ok(())
    }
}

impl CredentialEnrollmentStoreAuthority {
    /// Validates the issuer domain before durable recovery admission.
    pub fn validate_cleanup_recovery_request(
        &self,
        request: &CredentialCleanupRecoveryRequest,
    ) -> Result<(), CredentialEnrollmentError> {
        if !request.release.belongs_to(&self.seal)
            || !request.session.belongs_to(&self.seal)
            || !request.supervisor.belongs_to(&self.seal)
            || !request.continuation.belongs_to(&self.seal)
        {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        if request.database_generation == 0
            || request.database_generation > i64::MAX as u64
            || request.supervisor.generation() > i64::MAX as u64
            || request.ttl_seconds == 0
            || request.ttl_seconds > 300
            || request.continuation.digest() == request.session.digest()
            || request.continuation.digest() == request.release.digest()
        {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(())
    }

    /// Store-only publication after commit, analogous to verification lease issuance.
    /// The owning store must prove persistence ordering; this seal cannot do so.
    pub fn issue_cleanup_recovery(
        &self,
        request: CredentialCleanupRecoveryRequest,
        operation: super::super::CredentialOperationSnapshot,
        attempt: u64,
        issued_at: i64,
        expires_at: i64,
    ) -> Result<AcceptedCredentialCleanupRecovery, CredentialEnrollmentError> {
        self.validate_cleanup_recovery_request(&request)?;
        if attempt == 0
            || issued_at < 0
            || expires_at <= issued_at
            || operation.operation_id() != request.operation
            || operation.installation_owner_id() != request.owner
        {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        Ok(AcceptedCredentialCleanupRecovery {
            seal: self.seal.clone(),
            request,
            operation,
            attempt,
            issued_at,
            expires_at,
        })
    }

    /// Rejects a move-only witness published by another authority domain.
    pub fn validate_cleanup_recovery(
        &self,
        accepted: &AcceptedCredentialCleanupRecovery,
    ) -> Result<(), CredentialEnrollmentError> {
        if accepted.belongs_to(&self.seal) {
            Ok(())
        } else {
            Err(CredentialEnrollmentError::InvalidEvidence)
        }
    }
}
