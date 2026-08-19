use runne_domain::conversation::{ActiveTextGeneration, ConversationSnapshotV1, ConversationState};
use runne_domain::id::{AttemptId, ConversationId, MessageId, TaskRunId, WorkspaceId};
use runne_domain::message::MessageRole;
use runne_domain::task_run::TaskRunSnapshotV1;
use runne_domain::timestamp::Timestamp;
use std::fmt;

use super::{ApiReplayAggregateKind, ReplayContractError};

pub(super) const MAGIC: [u8; 4] = *b"GRPP";
pub(super) const VERSION: u8 = 1;
pub(super) const CONVERSATION_TAG: u8 = 1;
pub(super) const TASKRUN_TAG: u8 = 2;
mod codec;
mod local_json;
mod taskrun_getters;
mod taskrun_ids;
mod taskrun_map;
mod taskrun_types;
pub use local_json::canonical_local_promotion_json;
pub use taskrun_types::*;

/// Closed authoritative promotion-projection encoder.
///
/// Inputs are already-validated domain snapshots and exact persisted envelope
/// timestamps. The encoder returns only unauthenticated storage bytes.
pub struct ReplayPromotionProjectionV1;

/// Closed bytes parsed from untrusted storage into a read-only semantic view.
#[derive(Clone, PartialEq, Eq)]
pub struct UnauthenticatedReplayPromotionProjectionV1(ReplayPromotionProjectionViewV1);

/// Nonconstructible, read-only promoted aggregate state.
#[derive(Clone, PartialEq, Eq)]
pub enum ReplayPromotionProjectionViewV1 {
    /// Complete Conversation state and per-message commit timestamps.
    Conversation(ConversationPromotionViewV1),
    /// Complete typed TaskRun state without a live restore or raw-bytes API.
    TaskRun(Box<TaskRunPromotionViewV1>),
}

/// Read-only Conversation state suitable for local projection promotion.
#[derive(Clone, PartialEq, Eq)]
pub struct ConversationPromotionViewV1 {
    id: ConversationId,
    workspace_id: WorkspaceId,
    state: ConversationState,
    messages: Vec<ConversationPromotionMessageV1>,
    active_generation: Option<ActiveTextGeneration>,
    digest: [u8; 32],
}

/// One ordered Conversation message and its persisted envelope timestamp.
#[derive(Clone, PartialEq, Eq)]
pub struct ConversationPromotionMessageV1 {
    message_id: MessageId,
    role: MessageRole,
    taskrun_id: TaskRunId,
    attempt_id: AttemptId,
    text: String,
    committed_at_micros: i64,
}

/// Read-only semantic TaskRun state suitable for local projection promotion.
#[derive(Clone, PartialEq, Eq)]
pub struct TaskRunPromotionViewV1 {
    id: TaskRunId,
    state: TaskRunPromotionStateV1,
    digest: [u8; 32],
}

impl ReplayPromotionProjectionV1 {
    /// Encodes a Conversation snapshot with its exact per-message envelope times.
    pub fn encode_conversation(
        snapshot: &ConversationSnapshotV1,
        committed_at: &[Timestamp],
    ) -> Result<Vec<u8>, ReplayContractError> {
        if snapshot.messages().len() != committed_at.len()
            || committed_at.iter().any(|time| time.as_unix_micros() <= 0)
        {
            return Err(ReplayContractError::InvalidProjection);
        }
        let snapshot_bytes = snapshot
            .encode()
            .map_err(|_| ReplayContractError::InvalidProjection)?;
        let mut bytes = codec::header(CONVERSATION_TAG, snapshot.id().as_bytes(), &snapshot_bytes)?;
        codec::push_u32(&mut bytes, committed_at.len())?;
        for time in committed_at {
            codec::push(&mut bytes, &time.as_unix_micros().to_be_bytes())?;
        }
        Ok(bytes)
    }

    /// Encodes a complete closed TaskRun snapshot without a live restore seam.
    pub fn encode_task_run(snapshot: &TaskRunSnapshotV1) -> Result<Vec<u8>, ReplayContractError> {
        let snapshot_bytes = snapshot
            .encode()
            .map_err(|_| ReplayContractError::InvalidProjection)?;
        codec::header(TASKRUN_TAG, snapshot.id().as_bytes(), &snapshot_bytes)
    }
}

impl UnauthenticatedReplayPromotionProjectionV1 {
    /// Decodes exact versioned promotion bytes and validates all nested state.
    pub fn decode(bytes: &[u8]) -> Result<Self, ReplayContractError> {
        codec::decode(bytes).map(Self)
    }

    /// Returns the nonconstructible semantic view.
    pub const fn view(&self) -> &ReplayPromotionProjectionViewV1 {
        &self.0
    }
}

impl ConversationPromotionViewV1 {
    /// Returns canonical Conversation identity bytes.
    pub fn aggregate_id(&self) -> [u8; 16] {
        *self.id.as_bytes()
    }
    /// Returns canonical workspace identity bytes.
    pub fn workspace_id(&self) -> [u8; 16] {
        *self.workspace_id.as_bytes()
    }
    /// Returns the lifecycle state inherited from the closed domain snapshot.
    pub const fn state(&self) -> ConversationState {
        self.state
    }
    /// Returns exact ordered messages.
    pub fn messages(&self) -> &[ConversationPromotionMessageV1] {
        &self.messages
    }
    /// Returns an active generation binding, if present.
    pub const fn active_generation(&self) -> Option<&ActiveTextGeneration> {
        self.active_generation.as_ref()
    }
    /// Returns the domain-separated full-promotion digest.
    pub const fn projection_digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

impl ConversationPromotionMessageV1 {
    pub fn message_id(&self) -> [u8; 16] {
        *self.message_id.as_bytes()
    }
    pub const fn role(&self) -> MessageRole {
        self.role
    }
    pub fn taskrun_id(&self) -> [u8; 16] {
        *self.taskrun_id.as_bytes()
    }
    pub fn attempt_id(&self) -> [u8; 16] {
        *self.attempt_id.as_bytes()
    }
    pub fn text(&self) -> &str {
        &self.text
    }
    pub const fn committed_at_micros(&self) -> i64 {
        self.committed_at_micros
    }
}

impl TaskRunPromotionViewV1 {
    pub fn aggregate_id(&self) -> [u8; 16] {
        *self.id.as_bytes()
    }
    pub const fn semantic_state(&self) -> &TaskRunPromotionStateV1 {
        &self.state
    }
    pub const fn closed_snapshot_digest(&self) -> &[u8; 32] {
        &self.digest
    }
    /// Returns the digest binding the typed promotion state to its closed codec.
    pub const fn promotion_digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

impl fmt::Debug for UnauthenticatedReplayPromotionProjectionV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnauthenticatedReplayPromotionProjectionV1")
            .field("kind", &self.0.kind())
            .field("redacted", &true)
            .finish()
    }
}

impl ReplayPromotionProjectionViewV1 {
    const fn kind(&self) -> ApiReplayAggregateKind {
        match self {
            Self::Conversation(_) => ApiReplayAggregateKind::Conversation,
            Self::TaskRun(_) => ApiReplayAggregateKind::TaskRun,
        }
    }
}
