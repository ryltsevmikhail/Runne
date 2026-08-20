use runne_domain::conversation::{
    Conversation, ConversationSnapshotV1, MAX_REPLAY_BASELINE_PROJECTION_BYTES_V1 as DOMAIN_MAX,
};
use runne_domain::task_run::{TaskRun, TaskRunSnapshotV1};
use sha2::{Digest, Sha256};
use std::fmt;

/// Maximum closed replay-baseline projection payload size before any transport
/// envelope is added.
pub const MAX_REPLAY_BASELINE_PROJECTION_BYTES_V1: usize = DOMAIN_MAX;

/// Closed complete aggregate projection produced by authoritative replay.
///
/// It is not an authenticated replay baseline and never accepts a
/// caller-provided digest.
#[derive(Clone, PartialEq, Eq)]
pub enum ReplayAggregateProjectionV1 {
    /// Complete Conversation state.
    Conversation(ClosedConversationProjection),
    /// Complete TaskRun state.
    TaskRun(Box<ClosedTaskRunProjection>),
}

/// Validated complete Conversation state encoded by its domain-owned closed
/// codec. The raw bytes are immutable and only exposed for durable storage.
#[derive(Clone, PartialEq, Eq)]
pub struct ClosedConversationProjection {
    snapshot: ConversationSnapshotV1,
    bytes: Vec<u8>,
    digest: [u8; 32],
}

/// Validated complete TaskRun state encoded by its domain-owned closed codec.
#[derive(Clone, PartialEq, Eq)]
pub struct ClosedTaskRunProjection {
    snapshot: TaskRunSnapshotV1,
    bytes: Vec<u8>,
    digest: [u8; 32],
}

/// Closed bytes parsed from untrusted durable storage.
///
/// This is intentionally not an authenticated replay baseline. Its bytes must
/// still be bound to a retention witness and caller authorization by the next
/// contract layer before they can be disclosed to a client.
#[derive(Clone, PartialEq, Eq)]
pub struct UnauthenticatedReplayProjectionV1(ReplayAggregateProjectionV1);

impl fmt::Debug for ReplayAggregateProjectionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReplayAggregateProjectionV1")
            .field("aggregate_kind", &self.aggregate_kind())
            .field("aggregate_id", &self.aggregate_id())
            .field("redacted", &true)
            .finish()
    }
}

impl fmt::Debug for ClosedConversationProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClosedConversationProjection")
            .field("aggregate_id", &self.snapshot.id())
            .field("redacted", &true)
            .finish()
    }
}

impl fmt::Debug for ClosedTaskRunProjection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClosedTaskRunProjection")
            .field("aggregate_id", &self.snapshot.id())
            .field("redacted", &true)
            .finish()
    }
}

impl fmt::Debug for UnauthenticatedReplayProjectionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnauthenticatedReplayProjectionV1")
            .field("aggregate_kind", &self.aggregate_kind())
            .field("aggregate_id", &self.aggregate_id())
            .field("redacted", &true)
            .finish()
    }
}

impl ReplayAggregateProjectionV1 {
    /// Encodes one fully replayed Conversation state.
    pub fn from_conversation(conversation: &Conversation) -> Result<Self, ReplayContractError> {
        Self::from_snapshot(conversation.snapshot_v1())
    }

    /// Encodes one fully replayed TaskRun state.
    pub fn from_task_run(task_run: &TaskRun) -> Result<Self, ReplayContractError> {
        Self::from_taskrun_snapshot(task_run.snapshot_v1())
    }

    fn decode_conversation_bytes(bytes: &[u8]) -> Result<Self, ReplayContractError> {
        if bytes.len() > MAX_REPLAY_BASELINE_PROJECTION_BYTES_V1 {
            return Err(ReplayContractError::InvalidProjection);
        }
        Self::from_snapshot(
            ConversationSnapshotV1::decode(bytes)
                .map_err(|_| ReplayContractError::InvalidProjection)?,
        )
    }

    fn decode_task_run_bytes(bytes: &[u8]) -> Result<Self, ReplayContractError> {
        if bytes.len() > MAX_REPLAY_BASELINE_PROJECTION_BYTES_V1 {
            return Err(ReplayContractError::InvalidProjection);
        }
        Self::from_taskrun_snapshot(
            TaskRunSnapshotV1::decode(bytes).map_err(|_| ReplayContractError::InvalidProjection)?,
        )
    }

    /// Returns the exact aggregate kind.
    pub const fn aggregate_kind(&self) -> ApiReplayAggregateKind {
        match self {
            Self::Conversation(_) => ApiReplayAggregateKind::Conversation,
            Self::TaskRun(_) => ApiReplayAggregateKind::TaskRun,
        }
    }

    /// Returns the canonical aggregate identity bytes.
    pub fn aggregate_id(&self) -> [u8; 16] {
        match self {
            Self::Conversation(value) => *value.snapshot.id().as_bytes(),
            Self::TaskRun(value) => *value.snapshot.id().as_bytes(),
        }
    }

    /// Returns the deterministic domain-separated projection digest.
    pub const fn projection_digest(&self) -> &[u8; 32] {
        match self {
            Self::Conversation(value) => &value.digest,
            Self::TaskRun(value) => &value.digest,
        }
    }

    /// Returns exact closed bytes for persistence. A decoder must recompute the
    /// digest; the returned bytes are not a JSON or event-history format.
    pub fn encoded_bytes(&self) -> &[u8] {
        match self {
            Self::Conversation(value) => &value.bytes,
            Self::TaskRun(value) => &value.bytes,
        }
    }

    fn from_snapshot(snapshot: ConversationSnapshotV1) -> Result<Self, ReplayContractError> {
        let bytes = snapshot
            .encode()
            .map_err(|_| ReplayContractError::InvalidProjection)?;
        if bytes.len() > MAX_REPLAY_BASELINE_PROJECTION_BYTES_V1 {
            return Err(ReplayContractError::InvalidProjection);
        }
        let digest = projection_digest(
            ApiReplayAggregateKind::Conversation,
            snapshot.id().as_bytes(),
            &bytes,
        );
        Ok(Self::Conversation(ClosedConversationProjection {
            snapshot,
            bytes,
            digest,
        }))
    }

    fn from_taskrun_snapshot(snapshot: TaskRunSnapshotV1) -> Result<Self, ReplayContractError> {
        let bytes = snapshot
            .encode()
            .map_err(|_| ReplayContractError::InvalidProjection)?;
        if bytes.len() > MAX_REPLAY_BASELINE_PROJECTION_BYTES_V1 {
            return Err(ReplayContractError::InvalidProjection);
        }
        let digest = projection_digest(
            ApiReplayAggregateKind::TaskRun,
            snapshot.id().as_bytes(),
            &bytes,
        );
        Ok(Self::TaskRun(Box::new(ClosedTaskRunProjection {
            snapshot,
            bytes,
            digest,
        })))
    }
}

impl UnauthenticatedReplayProjectionV1 {
    /// Parses exact closed Conversation bytes from unauthenticated storage.
    pub fn decode_conversation_bytes(bytes: &[u8]) -> Result<Self, ReplayContractError> {
        ReplayAggregateProjectionV1::decode_conversation_bytes(bytes).map(Self)
    }

    /// Parses exact closed TaskRun bytes from unauthenticated storage.
    pub fn decode_task_run_bytes(bytes: &[u8]) -> Result<Self, ReplayContractError> {
        ReplayAggregateProjectionV1::decode_task_run_bytes(bytes).map(Self)
    }

    /// Returns the exact aggregate kind carried by these untrusted bytes.
    pub const fn aggregate_kind(&self) -> ApiReplayAggregateKind {
        self.0.aggregate_kind()
    }

    /// Returns the canonical aggregate identity bytes.
    pub fn aggregate_id(&self) -> [u8; 16] {
        self.0.aggregate_id()
    }

    /// Returns the recomputed projection digest.
    pub const fn projection_digest(&self) -> &[u8; 32] {
        self.0.projection_digest()
    }

    /// Returns exact bytes for persistence or later authenticated binding.
    pub fn encoded_bytes(&self) -> &[u8] {
        self.0.encoded_bytes()
    }
}

fn projection_digest(kind: ApiReplayAggregateKind, id: &[u8; 16], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"gocode.replay.aggregate-projection");
    hasher.update([0]);
    hasher.update([1]);
    hasher.update([match kind {
        ApiReplayAggregateKind::TaskRun => 1,
        ApiReplayAggregateKind::Conversation => 2,
    }]);
    hasher.update(id);
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}
