use crate::{
    QualificationFaultContext, QualificationFaultSelector, QualificationProcessRole,
    QualificationScenario, VerifiedQualificationFault, VerifiedQualificationRunContext,
};

/// Complete non-secret facts minted only by combined context-then-ticket verification.
pub struct VerifiedQualificationFenceFacts {
    context_id: [u8; 32],
    context_nonce: [u8; 32],
    ticket_id: [u8; 32],
    ticket_nonce: [u8; 32],
    scenario: QualificationScenario,
    selector: QualificationFaultSelector,
    process_role: QualificationProcessRole,
    candidate_sha256: [u8; 32],
    raw_v3_tuple_sha256: [u8; 32],
    source_revision: [u8; 20],
    workflow_run_id: String,
    namespace_sha256: [u8; 32],
    ticket_sha256: [u8; 32],
    context_issued_at: u64,
    context_expires_at: u64,
    ticket_issued_at: u64,
    ticket_expires_at: u64,
}

impl VerifiedQualificationFenceFacts {
    // By-value inputs intentionally consume both split verification authorities.
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn verified(
        context: VerifiedQualificationRunContext,
        fault: VerifiedQualificationFault,
        binding: QualificationFaultContext,
    ) -> Self {
        Self {
            context_id: context.context_id(),
            context_nonce: context.nonce(),
            ticket_id: fault.ticket_id(),
            ticket_nonce: fault.nonce(),
            scenario: binding.scenario,
            selector: binding.selector,
            process_role: binding.process_role,
            candidate_sha256: binding.candidate_sha256,
            raw_v3_tuple_sha256: binding.release_tuple_v3_sha256,
            source_revision: binding.source_revision,
            workflow_run_id: binding.workflow_run_id,
            namespace_sha256: binding.namespace_sha256,
            ticket_sha256: context.ticket_sha256(),
            context_issued_at: context.issued_at(),
            context_expires_at: context.expires_at(),
            ticket_issued_at: fault.issued_at(),
            ticket_expires_at: fault.expires_at(),
        }
    }

    #[must_use]
    pub const fn context_id(&self) -> [u8; 32] {
        self.context_id
    }
    #[must_use]
    pub const fn context_nonce(&self) -> [u8; 32] {
        self.context_nonce
    }
    #[must_use]
    pub const fn ticket_id(&self) -> [u8; 32] {
        self.ticket_id
    }
    #[must_use]
    pub const fn ticket_nonce(&self) -> [u8; 32] {
        self.ticket_nonce
    }
    #[must_use]
    pub const fn scenario(&self) -> QualificationScenario {
        self.scenario
    }
    #[must_use]
    pub const fn selector(&self) -> QualificationFaultSelector {
        self.selector
    }
    #[must_use]
    pub const fn process_role(&self) -> QualificationProcessRole {
        self.process_role
    }
    #[must_use]
    pub const fn candidate_sha256(&self) -> [u8; 32] {
        self.candidate_sha256
    }
    #[must_use]
    pub const fn raw_v3_tuple_sha256(&self) -> [u8; 32] {
        self.raw_v3_tuple_sha256
    }
    #[must_use]
    pub const fn source_revision(&self) -> [u8; 20] {
        self.source_revision
    }
    #[must_use]
    pub fn workflow_run_id(&self) -> &str {
        &self.workflow_run_id
    }
    #[must_use]
    pub const fn namespace_sha256(&self) -> [u8; 32] {
        self.namespace_sha256
    }
    #[must_use]
    pub const fn ticket_sha256(&self) -> [u8; 32] {
        self.ticket_sha256
    }
    #[must_use]
    pub const fn context_issued_at(&self) -> u64 {
        self.context_issued_at
    }
    #[must_use]
    pub const fn context_expires_at(&self) -> u64 {
        self.context_expires_at
    }
    #[must_use]
    pub const fn ticket_issued_at(&self) -> u64 {
        self.ticket_issued_at
    }
    #[must_use]
    pub const fn ticket_expires_at(&self) -> u64 {
        self.ticket_expires_at
    }
}
