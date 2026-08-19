//! Closed marker-safe terminal and audit evidence contracts.

use super::ProcessTerminalSettlementV1;
use core::fmt;

/// Closed audit lifecycle stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessAuditStageV1 {
    /// The operation was denied before an external effect.
    Denied,
    /// The effect was dispatched after claim projection.
    Dispatched,
    /// Exact terminal evidence was recorded.
    Terminal,
    /// The effect state is indeterminate and requires explicit reconciliation.
    Uncertain,
}

/// Immutable marker-safe audit record bound to unified settlement metadata.
#[derive(Clone, Eq, PartialEq)]
pub struct ProcessAuditRecordV1 {
    stage: ProcessAuditStageV1,
    settlement: ProcessTerminalSettlementV1,
}

impl ProcessAuditRecordV1 {
    #[cfg(test)]
    pub(crate) const fn new(
        stage: ProcessAuditStageV1,
        settlement: ProcessTerminalSettlementV1,
    ) -> Self {
        Self { stage, settlement }
    }

    /// Returns the immutable audit stage.
    #[must_use]
    pub const fn stage(&self) -> ProcessAuditStageV1 {
        self.stage
    }

    /// Returns immutable metadata-only settlement material.
    #[must_use]
    pub const fn settlement(&self) -> &ProcessTerminalSettlementV1 {
        &self.settlement
    }
}

impl fmt::Debug for ProcessAuditRecordV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProcessAuditRecordV1(redacted)")
    }
}
