use std::sync::Arc;

use super::EnrollmentAuthoritySeal;
use crate::credential::enrollment::{
    ClaimCredentialOperation, CredentialBindingDigest, CredentialClaimBinding,
    CredentialEnrollmentError, CredentialEnrollmentMeasurementAuthority,
    CredentialEnrollmentStoreAuthority, CredentialMeasurementSnapshot,
};

/// Private, authority-bound admission for one validated enrollment claim.
#[derive(Debug)]
pub(crate) struct ClaimOperationAdmission {
    seal: Arc<EnrollmentAuthoritySeal>,
    binding: CredentialClaimBinding,
}

impl ClaimOperationAdmission {
    pub(crate) fn seal(
        seal: Arc<EnrollmentAuthoritySeal>,
        binding: CredentialClaimBinding,
    ) -> Self {
        Self { seal, binding }
    }

    fn belongs_to(&self, seal: &Arc<EnrollmentAuthoritySeal>) -> bool {
        Arc::ptr_eq(&self.seal, seal)
    }

    fn digest(&self) -> CredentialBindingDigest {
        self.binding.digest()
    }
}

impl PartialEq for ClaimOperationAdmission {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.seal, &other.seal) && self.binding == other.binding
    }
}

impl Eq for ClaimOperationAdmission {}

impl CredentialEnrollmentStoreAuthority {
    /// Checks recovery session/release against the sealed live claim measurements.
    pub fn validate_cleanup_claim_context(
        &self,
        claim: &ClaimCredentialOperation,
        release: CredentialBindingDigest,
        session: CredentialBindingDigest,
    ) -> Result<(), CredentialEnrollmentError> {
        self.validate_claim_operation(claim)?;
        if claim
            .admission()
            .is_some_and(|admission| admission.binding.matches_recovery_context(release, session))
        {
            Ok(())
        } else {
            Err(CredentialEnrollmentError::InvalidEvidence)
        }
    }

    /// Returns the canonical claim digest only for this authority pair's sealed admission.
    pub fn validate_claim_operation(
        &self,
        claim: &ClaimCredentialOperation,
    ) -> Result<CredentialBindingDigest, CredentialEnrollmentError> {
        let admission = claim
            .admission()
            .ok_or(CredentialEnrollmentError::InvalidEvidence)?;
        if !admission.belongs_to(&self.seal) {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        Ok(admission.digest())
    }
}

impl CredentialEnrollmentMeasurementAuthority {
    /// Measures the canonical complete claim digest without admitting the draft.
    pub fn measure_claim_operation(
        &self,
        measurements: &CredentialMeasurementSnapshot,
        claim: &ClaimCredentialOperation,
    ) -> Result<CredentialBindingDigest, CredentialEnrollmentError> {
        if !measurements.belongs_to(&self.seal) {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        Ok(CredentialClaimBinding::measure(measurements.clone(), claim)?.digest())
    }

    /// Attaches one private admission after validating same-pair measurements and full claim data.
    pub fn seal_claim_operation(
        &self,
        measurements: CredentialMeasurementSnapshot,
        claim: ClaimCredentialOperation,
    ) -> Result<ClaimCredentialOperation, CredentialEnrollmentError> {
        if !measurements.belongs_to(&self.seal) {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        let binding = CredentialClaimBinding::new(measurements, &claim)?;
        Ok(claim.admit(ClaimOperationAdmission::seal(self.seal.clone(), binding)))
    }
}
