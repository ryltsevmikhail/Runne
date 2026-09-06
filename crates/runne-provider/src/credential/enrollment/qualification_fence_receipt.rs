use std::sync::Arc;

#[cfg(test)]
use super::ProviderQualificationAdmissionFence;
use super::{
    CredentialBindingDigest, CredentialEnrollmentError, CredentialOperationId,
    CredentialTicketAttempt, authority::EnrollmentAuthoritySeal,
};

/// Store-sealed proof that one exact replay fence committed with a real ticket attempt.
pub struct ProviderQualificationAdmissionFenceReceipt {
    seal: Arc<EnrollmentAuthoritySeal>,
    operation_id: CredentialOperationId,
    ticket_attempt: CredentialTicketAttempt,
    protected_session_digest: CredentialBindingDigest,
    runtime_authority_id: [u8; 16],
    database_generation: u64,
    launch_generation: u64,
    supervisor_generation: u64,
    effective_expires_at: i64,
    committed_at: i64,
    fingerprint: [u8; 32],
    continuation: CredentialBindingDigest,
}

#[allow(missing_docs)]
impl ProviderQualificationAdmissionFenceReceipt {
    pub(crate) fn committed(
        seal: Arc<EnrollmentAuthoritySeal>,
        admission: super::MeasuredQualificationAdmission,
        issued: &super::IssuedCredentialTicketAttempt,
    ) -> Result<Self, CredentialEnrollmentError> {
        let input = admission.metadata();
        let committed_at = issued.issued_at_high_water();
        let effective = input
            .effective_expires_at()
            .min(issued.expires_at_high_water());
        if !admission.belongs_to(&seal)
            || !issued.belongs_to(&seal)
            || input.operation_id() != issued.operation().operation_id()
            || committed_at < input.verified_at()
            || committed_at >= effective
        {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        Ok(Self {
            seal,
            operation_id: input.operation_id(),
            ticket_attempt: issued.ticket_attempt(),
            protected_session_digest: input.protected_session_digest(),
            runtime_authority_id: input.runtime_authority_id(),
            database_generation: input.database_generation(),
            launch_generation: input.launch_generation(),
            supervisor_generation: input.supervisor_generation(),
            effective_expires_at: effective,
            committed_at,
            fingerprint: admission.fingerprint(),
            continuation: admission.continuation_binding_digest(),
        })
    }

    #[cfg(test)]
    pub(crate) fn issue(
        seal: Arc<EnrollmentAuthoritySeal>,
        input: &ProviderQualificationAdmissionFence,
        ticket_attempt: CredentialTicketAttempt,
        committed_at: i64,
        provider_ticket_expires_at: i64,
    ) -> Result<Self, CredentialEnrollmentError> {
        let effective = input.effective_expires_at().min(provider_ticket_expires_at);
        if committed_at < input.verified_at() || committed_at >= effective {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            seal,
            operation_id: input.operation_id(),
            ticket_attempt,
            protected_session_digest: input.protected_session_digest(),
            runtime_authority_id: input.runtime_authority_id(),
            database_generation: input.database_generation(),
            launch_generation: input.launch_generation(),
            supervisor_generation: input.supervisor_generation(),
            effective_expires_at: effective,
            committed_at,
            fingerprint: [0; 32],
            continuation: input.protected_session_digest(),
        })
    }

    pub const fn operation_id(&self) -> CredentialOperationId {
        self.operation_id
    }
    pub const fn ticket_attempt(&self) -> CredentialTicketAttempt {
        self.ticket_attempt
    }
    pub const fn protected_session_digest(&self) -> CredentialBindingDigest {
        self.protected_session_digest
    }
    pub const fn runtime_authority_id(&self) -> [u8; 16] {
        self.runtime_authority_id
    }
    pub const fn database_generation(&self) -> u64 {
        self.database_generation
    }
    pub const fn launch_generation(&self) -> u64 {
        self.launch_generation
    }
    pub const fn supervisor_generation(&self) -> u64 {
        self.supervisor_generation
    }
    pub const fn effective_expires_at(&self) -> i64 {
        self.effective_expires_at
    }
    pub const fn committed_at(&self) -> i64 {
        self.committed_at
    }
    pub const fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }
    pub const fn continuation_binding_digest(&self) -> CredentialBindingDigest {
        self.continuation
    }
    pub(crate) fn belongs_to(&self, seal: &Arc<EnrollmentAuthoritySeal>) -> bool {
        Arc::ptr_eq(&self.seal, seal)
    }
}
