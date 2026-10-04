/// Closed duplicate-execution and cost acknowledgement required for a
/// successor to an unresolved external effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownSuccessorAcknowledgmentV1 {
    /// A second execution may duplicate remote work and charges.
    DuplicateExecutionAndCostV1,
}

impl UnknownSuccessorAcknowledgmentV1 {
    pub const CODE: &'static str = "duplicate_execution_and_cost_v1";
    pub const VERSION: u16 = 1;

    pub const fn code(self) -> &'static str {
        Self::CODE
    }

    pub const fn version(self) -> u16 {
        Self::VERSION
    }

    /// Stable digest bound into both aggregate markers and the successor row.
    pub fn digest(self) -> runne_domain::id::IntegrityDigest {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(b"runne-unknown-successor-ack\x01");
        hash.update(self.version().to_be_bytes());
        hash.update(self.code().as_bytes());
        runne_domain::id::IntegrityDigest::from_bytes(hash.finalize().into())
    }
}

/// Creates one explicitly acknowledged successor from an exact predecessor.
/// The caller cannot substitute prompt, profile, model, or command data.
#[derive(Debug, Clone, Copy)]
pub struct SupersedeUnknownTaskRunInput {
    /// Exact predecessor TaskRun.
    pub predecessor_taskrun_id: TaskRunId,
    /// Stream version displayed with the warning and still expected at commit.
    pub expected_predecessor_version: u64,
    /// Closed duplicate-execution and cost acknowledgment.
    pub acknowledgment: UnknownSuccessorAcknowledgmentV1,
}
