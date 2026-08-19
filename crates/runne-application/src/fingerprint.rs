//! Command fingerprint — SHA-256 canonical encoding for idempotency.
//!
//! Each use case has a typed constructor that produces a deterministic
//! 32-byte digest. The encoding includes:
//!   - Domain-separation prefix `runne-cmd\x01`
//!   - Schema version (u16, BE)
//!   - Operation tag (u8)
//!   - Length-prefixed semantic fields (u16 BE lengths)
//!   - Raw UUID bytes (16 bytes each)
//!   - TerminalResult canonical encoding (for complete only)
//!
//! Server-generated IDs (TaskRunId/AttemptId/EventId/CommandId) are
//! deliberately **not** included — a retry must return the original IDs.

use runne_domain::agent_loop::{
    LoopDisposition, StepOutcomeRecord, StepOutcomeType, WakeCondition, WakeEvidenceRef,
    WakeEvidenceSource,
};
use runne_domain::command::TerminalResult;
use runne_domain::context::ContextManifestRef;
use runne_domain::id::{ConversationId, IntegrityDigest, TaskRunId, WorkspaceId};
use runne_domain::message::MessageText;
use runne_domain::plan::PlanRevisionRef;
use runne_domain::recovery::ReconciliationResultRef;
use runne_domain::reference::{BudgetReservationRef, CheckpointRef, ResultRef};
use sha2::{Digest, Sha256};

pub use runne_api::MAX_CANONICAL_TERMINAL_REASON_BYTES as MAX_TERMINAL_REASON_BYTES;

use crate::commands::{
    ActivateScheduledRetryInput, CommitContextInput, CommitLoopCheckpointInput, CommitPlanInput,
    CommitRecoveryResumeInput, CompleteLoopCycleInput, CreateNextCycleInput,
    RecordStepOutcomeInput, ResumeLoopWaitInput, ScheduleRetryInput, StartLoopCycleInput,
};
use crate::errors::FingerprintError;

include!("fingerprint/encoding.rs");
include!("fingerprint/command.rs");

#[cfg(test)]
mod tests {
    use super::*;
    include!("fingerprint/tests/basic.rs");
    include!("fingerprint/tests/semantic.rs");
    include!("fingerprint/tests/golden.rs");
}
