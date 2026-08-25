use super::super::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialOperationId,
    CredentialTicketAttempt,
};

/// Durable digest-only record for one issued ticket and continuation attempt.
#[derive(Debug, PartialEq, Eq)]
pub struct IssueCredentialTicketDigest {
    operation_id: CredentialOperationId,
    ticket_attempt: CredentialTicketAttempt,
    ticket_digest: CredentialBindingDigest,
    continuation_binding_digest: CredentialBindingDigest,
    issued_at_high_water: i64,
    expires_at_high_water: i64,
}

impl IssueCredentialTicketDigest {
    /// Validates digest-only ticket metadata; raw ticket bytes never enter the port.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        operation_id: CredentialOperationId,
        ticket_attempt: CredentialTicketAttempt,
        ticket_digest: CredentialBindingDigest,
        continuation_binding_digest: CredentialBindingDigest,
        issued_at_high_water: i64,
        expires_at_high_water: i64,
    ) -> Result<Self, CredentialEnrollmentError> {
        if issued_at_high_water < 0 || expires_at_high_water <= issued_at_high_water {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            operation_id,
            ticket_attempt,
            ticket_digest,
            continuation_binding_digest,
            issued_at_high_water,
            expires_at_high_water,
        })
    }

    /// Returns the operation identity.
    pub const fn operation_id(&self) -> CredentialOperationId {
        self.operation_id
    }
    /// Returns the ticket attempt.
    pub const fn ticket_attempt(&self) -> CredentialTicketAttempt {
        self.ticket_attempt
    }
    /// Returns the durable ticket digest.
    pub const fn ticket_digest(&self) -> CredentialBindingDigest {
        self.ticket_digest
    }
    /// Returns the accepted continuation binding digest.
    pub const fn continuation_binding_digest(&self) -> CredentialBindingDigest {
        self.continuation_binding_digest
    }
    /// Returns the issue timestamp.
    pub const fn issued_at_high_water(&self) -> i64 {
        self.issued_at_high_water
    }
    /// Returns the expiry timestamp.
    pub const fn expires_at_high_water(&self) -> i64 {
        self.expires_at_high_water
    }
}
