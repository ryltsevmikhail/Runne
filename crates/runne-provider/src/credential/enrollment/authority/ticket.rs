use super::CredentialEnrollmentStoreAuthority;
use crate::credential::enrollment::{
    CredentialEnrollmentError, CredentialOperationSnapshot, CredentialTicketAttempt,
    IssuedCredentialTicketAttempt,
};

impl CredentialEnrollmentStoreAuthority {
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
