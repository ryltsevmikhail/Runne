use super::CredentialEnrollmentStoreAuthority;
use crate::credential::enrollment::{
    CredentialEnrollmentError, CredentialOperationSnapshot, CredentialTicketAttempt,
    IssuedCredentialTicketAttempt,
};

impl CredentialEnrollmentStoreAuthority {
    #[cfg(test)]
    pub(crate) fn hydrate_qualification_admission_fence_receipt_for_test(
        &self,
        input: &crate::ProviderQualificationAdmissionFence,
        attempt: CredentialTicketAttempt,
        committed_at: i64,
        provider_ticket_expires_at: i64,
    ) -> Result<crate::ProviderQualificationAdmissionFenceReceipt, CredentialEnrollmentError> {
        crate::ProviderQualificationAdmissionFenceReceipt::issue(
            self.seal.clone(),
            input,
            attempt,
            committed_at,
            provider_ticket_expires_at,
        )
    }

    /// Rejects a qualification commit receipt from another store authority domain.
    pub fn validate_qualification_admission_fence_receipt(
        &self,
        receipt: &crate::ProviderQualificationAdmissionFenceReceipt,
    ) -> Result<(), CredentialEnrollmentError> {
        if receipt.belongs_to(&self.seal) {
            Ok(())
        } else {
            Err(CredentialEnrollmentError::InvalidEvidence)
        }
    }

    /// Hydrates one receipt only after this store authority has committed its exact ticket row.
    pub fn hydrate_issued_credential_ticket_attempt(
        &self,
        operation: CredentialOperationSnapshot,
        ticket_attempt: CredentialTicketAttempt,
        issued_at_high_water: i64,
        expires_at_high_water: i64,
    ) -> Result<IssuedCredentialTicketAttempt, CredentialEnrollmentError> {
        IssuedCredentialTicketAttempt::issue(
            self.seal.clone(),
            operation,
            ticket_attempt,
            issued_at_high_water,
            expires_at_high_water,
        )
    }

    /// Rejects a receipt not hydrated by this exact store authority pair.
    pub fn validate_issued_credential_ticket_attempt(
        &self,
        receipt: &IssuedCredentialTicketAttempt,
    ) -> Result<(), CredentialEnrollmentError> {
        if receipt.belongs_to(&self.seal) {
            Ok(())
        } else {
            Err(CredentialEnrollmentError::InvalidEvidence)
        }
    }
}
