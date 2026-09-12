use std::fmt;

use crate::{QualificationFaultSelector, QualificationProcessRole};

/// Closed qualification scenario asserted by the runner authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationScenario {
    MacosXpcDpkV1,
}

impl QualificationScenario {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MacosXpcDpkV1 => "macos-xpc-dpk-v1",
        }
    }

    pub(super) fn parse(value: &str) -> Option<Self> {
        match value {
            "macos-xpc-dpk-v1" => Some(Self::MacosXpcDpkV1),
            _ => None,
        }
    }
}

/// Independently measured facts expected from one signed runner context.
pub struct QualificationRunContextExpectation {
    pub(super) scenario: QualificationScenario,
    pub(super) selector: QualificationFaultSelector,
    pub(super) process_role: QualificationProcessRole,
    pub(super) candidate_sha256: [u8; 32],
    pub(super) release_tuple_v3_sha256: [u8; 32],
    pub(super) source_revision: [u8; 20],
    pub(super) workflow_run_id: String,
    pub(super) namespace_sha256: [u8; 32],
    pub(super) ticket_sha256: [u8; 32],
}

impl QualificationRunContextExpectation {
    /// Constructs exact independently supplied runner-context expectations.
    ///
    /// # Errors
    ///
    /// Rejects a noncanonical workflow ID or selector/role mismatch.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scenario: QualificationScenario,
        selector: QualificationFaultSelector,
        process_role: QualificationProcessRole,
        candidate_sha256: [u8; 32],
        release_tuple_v3_sha256: [u8; 32],
        source_revision: [u8; 20],
        workflow_run_id: &str,
        namespace_sha256: [u8; 32],
        ticket_sha256: [u8; 32],
    ) -> Result<Self, QualificationRunContextError> {
        if selector.process_role() != process_role || !crate::model::valid_run_id(workflow_run_id) {
            return Err(QualificationRunContextError::InvalidExpectation);
        }
        Ok(Self {
            scenario,
            selector,
            process_role,
            candidate_sha256,
            release_tuple_v3_sha256,
            source_revision,
            workflow_run_id: workflow_run_id.to_owned(),
            namespace_sha256,
            ticket_sha256,
        })
    }

    pub(crate) fn has_nonzero_installed_hashes(&self) -> bool {
        self.candidate_sha256 != [0; 32] && self.release_tuple_v3_sha256 != [0; 32]
    }

    pub(crate) fn fault_context(
        &self,
    ) -> Result<crate::QualificationFaultContext, QualificationRunContextError> {
        crate::QualificationFaultContext::new(
            self.selector,
            self.process_role,
            self.candidate_sha256,
            self.release_tuple_v3_sha256,
            self.source_revision,
            &self.workflow_run_id,
            self.namespace_sha256,
        )
        .map_err(|_| QualificationRunContextError::InvalidExpectation)
    }
}

/// Opaque single-use authority produced after exact runner-context verification.
pub struct VerifiedQualificationRunContext {
    context_id: [u8; 32],
    nonce: [u8; 32],
    issued_at: u64,
    expires_at: u64,
    ticket_sha256: [u8; 32],
}

impl VerifiedQualificationRunContext {
    pub(super) const fn verified(
        context_id: [u8; 32],
        nonce: [u8; 32],
        issued_at: u64,
        expires_at: u64,
        ticket_sha256: [u8; 32],
    ) -> Self {
        Self {
            context_id,
            nonce,
            issued_at,
            expires_at,
            ticket_sha256,
        }
    }

    #[must_use]
    pub const fn context_id(&self) -> [u8; 32] {
        self.context_id
    }

    #[must_use]
    pub const fn nonce(&self) -> [u8; 32] {
        self.nonce
    }

    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    #[must_use]
    pub const fn ticket_sha256(&self) -> [u8; 32] {
        self.ticket_sha256
    }

    pub(crate) const fn issued_at(&self) -> u64 {
        self.issued_at
    }
}

/// Closed failure classes for signed runner-context verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationRunContextError {
    PolicyUnavailable,
    InvalidExpectation,
    InvalidContext,
    InvalidTime,
    InvalidSignature,
    BindingMismatch,
    Replay,
}

impl fmt::Display for QualificationRunContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("qualification runner context rejected")
    }
}

impl std::error::Error for QualificationRunContextError {}
