//! Durable codec — encodes and decodes domain types for SQLite BLOB storage.
//!
//! Each codec implements [`StoreCodec`] with a versioned encoding format.
//! Decoding must reject: unknown tags, trailing bytes, oversized values,
//! and unsupported codec versions.

use core::{fmt, str::FromStr};

use gocode_application::commands::CommandOutcome;
use gocode_application::ports::{
    AggregateScope, ConversationReceipt, IdempotencyScope, OperationTag, TextGenerationPhase,
    TextGenerationReceipt,
};
use gocode_domain::agent_loop::{
    LoopCheckpointBody, LoopDisposition, StepOutcomeRecord, StepOutcomeRef, StepOutcomeType,
    WakeCondition, WakeConditionKind, WakeEvidenceRef, WakeEvidenceSource,
};
use gocode_domain::command::TerminalResult;
use gocode_domain::context::ContextManifestRef;
use gocode_domain::conversation::{ConversationEvent, GenerationFailureReason};
use gocode_domain::id::{
    AttemptId, BudgetReservationId, CheckpointId, ContextManifestId, ConversationId, CycleId,
    EffectId, IntegrityDigest, MessageId, PlanEvaluationId, PlanId, ReconciliationRunId, ResultId,
    StepId, TaskRunId, WakeEvidenceId, WorkspaceId,
};
use gocode_domain::message::{MAX_MESSAGE_TEXT_BYTES, MessageText};
use gocode_domain::plan::{PlanParentRef, PlanRevisionRef};
use gocode_domain::recovery::{ReconciliationResultRef, ReconciliationStatus};
use gocode_domain::reference::{BudgetReservationRef, CheckpointRef, ResultRef};
use gocode_domain::task_run::{TaskRunEvent, TaskRunState};
use gocode_domain::verification::{PlanEvaluationRef, PlanEvaluationResult};

/// Error from a codec encode/decode operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreCodecError {
    /// Unsupported codec version.
    UnsupportedVersion {
        /// The version found in the encoded bytes.
        found: u16,
        /// The version this codec supports.
        supported: u16,
    },
    /// Unknown event tag in the encoded bytes.
    UnknownTag {
        /// The tag byte that was not recognized.
        tag: u8,
        /// Context for debugging (e.g., "TaskRunEvent").
        context: &'static str,
    },
    /// Not enough bytes to decode the value.
    Truncated,
    /// Extra bytes remaining after decoding.
    TrailingBytes {
        /// The number of extra bytes remaining.
        remaining: usize,
    },
    /// A value exceeds its maximum allowed size.
    Oversized {
        /// What was oversized.
        field: &'static str,
        /// The maximum allowed size.
        max: usize,
        /// The actual size.
        actual: usize,
    },
    /// Structurally present bytes violate a closed domain invariant.
    InvalidValue {
        /// Non-sensitive decoding context.
        context: &'static str,
    },
}

impl fmt::Display for StoreCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion { found, supported } => {
                write!(
                    f,
                    "unsupported codec version: found {}, supported {}",
                    found, supported
                )
            }
            Self::UnknownTag { tag, context } => {
                write!(f, "unknown tag 0x{:02x} in {}", tag, context)
            }
            Self::Truncated => write!(f, "truncated bytes"),
            Self::TrailingBytes { remaining } => {
                write!(f, "trailing bytes after decode: {}", remaining)
            }
            Self::Oversized { field, max, actual } => {
                write!(
                    f,
                    "{} exceeds max size: max={}, actual={}",
                    field, max, actual
                )
            }
            Self::InvalidValue { context } => write!(f, "invalid value in {context}"),
        }
    }
}

impl std::error::Error for StoreCodecError {}

/// Trait for durable encoding/decoding of a type to/from BLOB bytes.
pub trait StoreCodec<T: Sized> {
    /// The codec version (incremented when encoding changes).
    const CODEC_VERSION: u16;

    /// Encode a value to bytes.
    fn encode(&self, value: &T) -> Result<Vec<u8>, StoreCodecError>;

    /// Decode bytes back into a value.
    fn decode(&self, bytes: &[u8]) -> Result<T, StoreCodecError>;
}

// ── Helpers ──────────────────────────────────────────────────────────────

mod command;
mod conversation;
mod loop_refs;
mod primitives;
mod project_workspace;
mod receipts;
mod refs;
mod task_run;
#[cfg(test)]
mod tests;

pub use command::CommandOutcomeCodec;
pub use conversation::ConversationEventCodec;
pub(crate) use project_workspace::MAX_REHYDRATED_VERSION;
pub use project_workspace::{ProjectWorkspaceReceipt, ProjectWorkspaceReceiptCodec};
pub use receipts::{ConversationReceiptCodec, IdempotencyScopeCodec, TextGenerationReceiptCodec};
pub use task_run::TaskRunEventCodec;
