use crate::credential::enrollment::{
    CredentialEnrollmentError, CredentialEnrollmentMeasurementAuthority,
    CredentialMeasurementSnapshot,
};

impl CredentialEnrollmentMeasurementAuthority {
    /// Rejects a measurement snapshot not issued by this authority pair.
    pub fn validate_measurement_snapshot(
        &self,
        snapshot: &CredentialMeasurementSnapshot,
    ) -> Result<(), CredentialEnrollmentError> {
        snapshot
            .belongs_to(&self.seal)
            .then_some(())
            .ok_or(CredentialEnrollmentError::InvalidEvidence)
    }
}
