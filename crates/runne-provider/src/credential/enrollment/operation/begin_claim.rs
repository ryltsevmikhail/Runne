use crate::{CredentialVersionRef, ProviderId};

use super::super::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationAction, CredentialOperationId,
};
use super::ticket::IssuedCredentialTicketAttempt;
use crate::credential::enrollment::authority::claim::ClaimOperationAdmission;

/// Digest-only claim bound to one immutable store-issued ticket receipt.
#[derive(Debug, PartialEq, Eq)]
pub struct ClaimCredentialOperation {
    receipt: IssuedCredentialTicketAttempt,
    ticket_digest: CredentialBindingDigest,
    continuation_binding_digest: CredentialBindingDigest,
    process_release_binding_digest: CredentialBindingDigest,
    database_generation: u64,
    desktop_supervisor_generation: u64,
    admission: Option<ClaimOperationAdmission>,
}

#[allow(missing_docs)]
impl ClaimCredentialOperation {
    /// Validates one claim whose attempt and timestamps can only come from the receipt.
    pub fn new(
        receipt: IssuedCredentialTicketAttempt,
        ticket_digest: CredentialBindingDigest,
        continuation_binding_digest: CredentialBindingDigest,
        process_release_binding_digest: CredentialBindingDigest,
        database_generation: u64,
        desktop_supervisor_generation: u64,
    ) -> Result<Self, CredentialEnrollmentError> {
        if database_generation == 0 || desktop_supervisor_generation == 0 {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            receipt,
            ticket_digest,
            continuation_binding_digest,
            process_release_binding_digest,
            database_generation,
            desktop_supervisor_generation,
            admission: None,
        })
    }

    pub const fn operation_id(&self) -> CredentialOperationId {
        self.receipt.operation().operation_id()
    }
    pub const fn installation_owner_id(&self) -> super::super::CredentialInstallationOwnerId {
        self.receipt.operation().installation_owner_id()
    }
    pub const fn ticket_attempt(&self) -> super::super::CredentialTicketAttempt {
        self.receipt.ticket_attempt()
    }
    pub const fn ticket_digest(&self) -> CredentialBindingDigest {
        self.ticket_digest
    }
    pub const fn continuation_binding_digest(&self) -> CredentialBindingDigest {
        self.continuation_binding_digest
    }
    pub const fn process_release_binding_digest(&self) -> CredentialBindingDigest {
        self.process_release_binding_digest
    }
    pub fn bind_process_release_digest(
        mut self,
        digest: CredentialBindingDigest,
    ) -> Result<Self, CredentialEnrollmentError> {
        if self.admission.is_some() {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        self.process_release_binding_digest = digest;
        Ok(self)
    }
    pub const fn provider_id(&self) -> &ProviderId {
        self.receipt.operation().provider()
    }
    pub const fn action(&self) -> CredentialOperationAction {
        self.receipt.operation().action()
    }
    pub const fn allocated_credential_version(&self) -> Option<&CredentialVersionRef> {
        self.receipt.operation().allocated_credential_version()
    }
    pub const fn target_credential_version(&self) -> Option<&CredentialVersionRef> {
        self.receipt.operation().target_credential_version()
    }
    pub const fn effect_credential_version(&self) -> Option<&CredentialVersionRef> {
        match self.allocated_credential_version() {
            Some(version) => Some(version),
            None => self.target_credential_version(),
        }
    }
    pub const fn expected_lifecycle_revision(&self) -> CredentialLifecycleRevision {
        self.receipt.operation().lifecycle_revision()
    }
    pub const fn expected_prior_fence(&self) -> CredentialFence {
        self.receipt.operation().fence()
    }
    pub const fn database_generation(&self) -> u64 {
        self.database_generation
    }
    pub const fn desktop_supervisor_generation(&self) -> u64 {
        self.desktop_supervisor_generation
    }
    pub const fn issued_at_high_water(&self) -> i64 {
        self.receipt.issued_at_high_water()
    }
    pub const fn expires_at_high_water(&self) -> i64 {
        self.receipt.expires_at_high_water()
    }
    pub const fn receipt(&self) -> &IssuedCredentialTicketAttempt {
        &self.receipt
    }

    pub(crate) fn admit(mut self, admission: ClaimOperationAdmission) -> Self {
        self.admission = Some(admission);
        self
    }
    pub(crate) fn admission(&self) -> Option<&ClaimOperationAdmission> {
        self.admission.as_ref()
    }
}
