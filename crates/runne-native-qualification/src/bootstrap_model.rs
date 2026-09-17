use std::fmt;

/// Exact independently measured bindings for one signed bootstrap run proof.
pub struct QualificationRunBootstrapExpectation {
    pub(super) candidate_sha256: [u8; 32],
    pub(super) raw_v3_tuple_sha256: [u8; 32],
    pub(super) source_revision: [u8; 20],
    pub(super) workflow_run_id: String,
    pub(super) namespace_sha256: [u8; 32],
    pub(super) manifest_sha256: [u8; 32],
    pub(super) profile_sha256: [u8; 32],
    pub(super) context_id: [u8; 32],
    pub(super) nonce: [u8; 32],
    pub(super) challenge: [u8; 32],
    pub(super) issued_at: u64,
    pub(super) expires_at: u64,
    pub(super) run_not_after: u64,
    pub(super) max_run_duration_seconds: u64,
}

impl QualificationRunBootstrapExpectation {
    /// Constructs the complete independently supplied bootstrap binding.
    ///
    /// # Errors
    ///
    /// Rejects zero security identities, noncanonical workflow identifiers, or
    /// an invalid admission window.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        candidate_sha256: [u8; 32],
        raw_v3_tuple_sha256: [u8; 32],
        source_revision: [u8; 20],
        workflow_run_id: &str,
        namespace_sha256: [u8; 32],
        manifest_sha256: [u8; 32],
        profile_sha256: [u8; 32],
        context_id: [u8; 32],
        nonce: [u8; 32],
        challenge: [u8; 32],
        issued_at: u64,
        expires_at: u64,
        run_not_after: u64,
        max_run_duration_seconds: u64,
    ) -> Result<Self, QualificationRunBootstrapError> {
        let hashes = [
            candidate_sha256,
            raw_v3_tuple_sha256,
            namespace_sha256,
            manifest_sha256,
            profile_sha256,
            context_id,
            nonce,
            challenge,
        ];
        if hashes.into_iter().any(|value| value == [0; 32])
            || source_revision == [0; 20]
            || !crate::model::valid_run_id(workflow_run_id)
            || !crate::bootstrap_verification::valid_admission_window(issued_at, expires_at)
            || !crate::bootstrap_verification::valid_run_deadline(
                issued_at,
                expires_at,
                run_not_after,
                max_run_duration_seconds,
            )
        {
            return Err(QualificationRunBootstrapError::InvalidExpectation);
        }
        Ok(Self {
            candidate_sha256,
            raw_v3_tuple_sha256,
            source_revision,
            workflow_run_id: workflow_run_id.to_owned(),
            namespace_sha256,
            manifest_sha256,
            profile_sha256,
            context_id,
            nonce,
            challenge,
            issued_at,
            expires_at,
            run_not_after,
            max_run_duration_seconds,
        })
    }
}

/// Opaque move-only facts produced only by exact signed run-proof verification.
///
/// These facts establish neither durable replay admission nor bootstrap authority.
/// A durable ledger must consume them before a bootstrap path can use the proof.
pub struct VerifiedQualificationRunBootstrapProof {
    candidate_sha256: [u8; 32],
    raw_v3_tuple_sha256: [u8; 32],
    source_revision: [u8; 20],
    workflow_run_id: String,
    namespace_sha256: [u8; 32],
    manifest_sha256: [u8; 32],
    profile_sha256: [u8; 32],
    context_id: [u8; 32],
    nonce: [u8; 32],
    challenge: [u8; 32],
    issued_at: u64,
    expires_at: u64,
    run_not_after: u64,
}

impl VerifiedQualificationRunBootstrapProof {
    pub(super) fn verified(expected: &QualificationRunBootstrapExpectation) -> Self {
        Self {
            candidate_sha256: expected.candidate_sha256,
            raw_v3_tuple_sha256: expected.raw_v3_tuple_sha256,
            source_revision: expected.source_revision,
            workflow_run_id: expected.workflow_run_id.clone(),
            namespace_sha256: expected.namespace_sha256,
            manifest_sha256: expected.manifest_sha256,
            profile_sha256: expected.profile_sha256,
            context_id: expected.context_id,
            nonce: expected.nonce,
            challenge: expected.challenge,
            issued_at: expected.issued_at,
            expires_at: expected.expires_at,
            run_not_after: expected.run_not_after,
        }
    }

    /// Domain-separated digest of the exact verified bootstrap row.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        use sha2::{Digest as _, Sha256};
        let mut digest = Sha256::new();
        digest.update(b"runne/qualification-run-bootstrap-proof/v1\0");
        for value in [
            self.candidate_sha256,
            self.raw_v3_tuple_sha256,
            self.namespace_sha256,
            self.manifest_sha256,
            self.profile_sha256,
            self.context_id,
            self.nonce,
            self.challenge,
        ] {
            digest.update(value);
        }
        digest.update(self.source_revision);
        digest.update((self.workflow_run_id.len() as u64).to_be_bytes());
        digest.update(self.workflow_run_id.as_bytes());
        digest.update(self.issued_at.to_be_bytes());
        digest.update(self.expires_at.to_be_bytes());
        digest.update(self.run_not_after.to_be_bytes());
        digest.finalize().into()
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
    pub const fn manifest_sha256(&self) -> [u8; 32] {
        self.manifest_sha256
    }
    #[must_use]
    pub const fn profile_sha256(&self) -> [u8; 32] {
        self.profile_sha256
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
    pub const fn challenge(&self) -> [u8; 32] {
        self.challenge
    }
    #[must_use]
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
    #[must_use]
    pub const fn run_not_after(&self) -> u64 {
        self.run_not_after
    }
}

/// Closed signed bootstrap-proof rejection classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationRunBootstrapError {
    PolicyUnavailable,
    InvalidExpectation,
    InvalidProof,
    InvalidTime,
    InvalidSignature,
    BindingMismatch,
    Replay,
}

impl fmt::Display for QualificationRunBootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("qualification run bootstrap proof rejected")
    }
}

impl std::error::Error for QualificationRunBootstrapError {}
