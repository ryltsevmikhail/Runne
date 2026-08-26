use std::sync::Arc;

use super::super::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialOperationId,
    CredentialOperationSnapshot, CredentialOperationState, CredentialTicketAttempt,
};
use crate::credential::enrollment::authority::EnrollmentAuthoritySeal;

const MAX_TICKET_TTL_SECONDS: i64 = 3600;

/// Digest-only request for a store-owned ticket attempt.
#[derive(Debug, PartialEq, Eq)]
pub struct IssueCredentialTicketDigest {
    operation_id: CredentialOperationId,
    ticket_digest: CredentialBindingDigest,
    continuation_binding_digest: CredentialBindingDigest,
    ticket_ttl_seconds: i64,
}

#[allow(missing_docs)]
impl IssueCredentialTicketDigest {
    /// Validates bounded digest-only ticket data; attempt and timestamps are store-owned.
    pub fn new(
        operation_id: CredentialOperationId,
        ticket_digest: CredentialBindingDigest,
        continuation_binding_digest: CredentialBindingDigest,
        ticket_ttl_seconds: i64,
    ) -> Result<Self, CredentialEnrollmentError> {
        if !(1..=MAX_TICKET_TTL_SECONDS).contains(&ticket_ttl_seconds) {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            operation_id,
            ticket_digest,
            continuation_binding_digest,
            ticket_ttl_seconds,
        })
    }

    pub const fn operation_id(&self) -> CredentialOperationId {
        self.operation_id
    }
    pub const fn ticket_digest(&self) -> CredentialBindingDigest {
        self.ticket_digest
    }
    pub const fn continuation_binding_digest(&self) -> CredentialBindingDigest {
        self.continuation_binding_digest
    }
    pub const fn ticket_ttl_seconds(&self) -> i64 {
        self.ticket_ttl_seconds
    }
}

/// Store-issued immutable ticket receipt used to claim one exact attempt.
///
/// ```compile_fail
/// use runne_provider::IssuedCredentialTicketAttempt;
/// let _ = IssuedCredentialTicketAttempt::new;
/// ```
#[derive(Clone, Debug)]
pub struct IssuedCredentialTicketAttempt {
    seal: Arc<EnrollmentAuthoritySeal>,
    operation: CredentialOperationSnapshot,
    ticket_attempt: CredentialTicketAttempt,
    issued_at_high_water: i64,
    expires_at_high_water: i64,
}

#[allow(missing_docs)]
impl IssuedCredentialTicketAttempt {
    pub(crate) fn issue(
        seal: Arc<EnrollmentAuthoritySeal>,
        operation: CredentialOperationSnapshot,
        ticket_attempt: CredentialTicketAttempt,
        issued_at_high_water: i64,
        expires_at_high_water: i64,
    ) -> Result<Self, CredentialEnrollmentError> {
        if operation.state() != CredentialOperationState::Prepared
            || issued_at_high_water < 0
            || expires_at_high_water <= issued_at_high_water
        {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            seal,
            operation,
            ticket_attempt,
            issued_at_high_water,
            expires_at_high_water,
        })
    }

    pub const fn operation(&self) -> &CredentialOperationSnapshot {
        &self.operation
    }
    pub const fn ticket_attempt(&self) -> CredentialTicketAttempt {
        self.ticket_attempt
    }
    pub const fn issued_at_high_water(&self) -> i64 {
        self.issued_at_high_water
    }
    pub const fn expires_at_high_water(&self) -> i64 {
        self.expires_at_high_water
    }

    pub(crate) fn belongs_to(&self, seal: &Arc<EnrollmentAuthoritySeal>) -> bool {
        Arc::ptr_eq(&self.seal, seal)
    }
}

impl PartialEq for IssuedCredentialTicketAttempt {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.seal, &other.seal)
            && self.operation == other.operation
            && self.ticket_attempt == other.ticket_attempt
            && self.issued_at_high_water == other.issued_at_high_water
            && self.expires_at_high_water == other.expires_at_high_water
    }
}

impl Eq for IssuedCredentialTicketAttempt {}
