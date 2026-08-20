/// Opaque ackable replay cursor.
///
/// Cursor wire bytes are restricted to this client's private wire module.
/// Native persistence must use a dedicated adapter rather than this wrapper;
/// the public cursor API intentionally exposes no byte codec.
///
/// ```compile_fail
/// use runne_runtime_client::ReplayCursor;
///
/// fn leak_cursor_bytes(cursor: &ReplayCursor) {
///     let _ = cursor.storage_bytes();
/// }
/// ```
///
/// ```compile_fail
/// use runne_runtime_client::ReplayCursor;
///
/// fn decode_cursor_bytes() {
///     let _ = ReplayCursor::from_storage_bytes(b"gocode-replay-cursor-v1.7b7d");
/// }
/// ```
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ReplayCursor(pub(super) String);

/// Opaque replay session identity.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ReplaySessionId(pub(super) [u8; 16]);

/// Opaque live-delivery identity.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct LiveDeliveryId(pub(super) CanonicalId);

/// Published Aggregate replay scope.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReplayAggregateKind {
    Conversation,
    TaskRun,
}

impl ReplayAggregateKind {
    pub(super) const fn wire_value(self) -> &'static str {
        match self {
            Self::Conversation => "conversation",
            Self::TaskRun => "taskRun",
        }
    }

    pub(super) fn parse(value: &str) -> Result<Self, ReplayClientError> {
        match value {
            "conversation" => Ok(Self::Conversation),
            "taskRun" => Ok(Self::TaskRun),
            _ => Err(ReplayClientError::new(
                ReplayClientErrorKind::SchemaMismatch,
            )),
        }
    }
}

/// One exact Aggregate replay selector.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReplayScope {
    pub(super) aggregate_kind: ReplayAggregateKind,
    pub(super) aggregate_id: CanonicalId,
}

impl ReplayScope {
    #[must_use]
    pub const fn new(aggregate_kind: ReplayAggregateKind, aggregate_id: CanonicalId) -> Self {
        Self {
            aggregate_kind,
            aggregate_id,
        }
    }

    #[must_use]
    pub const fn aggregate_kind(self) -> ReplayAggregateKind {
        self.aggregate_kind
    }

    #[must_use]
    pub const fn aggregate_id(self) -> CanonicalId {
        self.aggregate_id
    }
}

/// Closed replay sensitivity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplaySensitivity {
    Public,
    Internal,
    Sensitive,
}

/// Validated Conversation payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConversationReplayPayload {
    Created {
        workspace_id: CanonicalId,
    },
    MessageAppended {
        role: crate::ConversationMessageRole,
        message_id: CanonicalId,
        task_run_id: CanonicalId,
        attempt_id: CanonicalId,
        text: String,
    },
    GenerationFailed {
        task_run_id: CanonicalId,
        attempt_id: CanonicalId,
        reason: String,
    },
    Closed,
}

/// Validated closed `TaskRun` payload.
///
/// `TaskRun` projection is outside the Desktop slice, so the semantic value is
/// retained as validated public JSON while its event type remains explicit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskRunReplayPayload {
    pub(super) event_type: String,
    pub(super) value: serde_json::Value,
}

impl TaskRunReplayPayload {
    #[must_use]
    pub fn event_type(&self) -> &str {
        &self.event_type
    }

    #[must_use]
    pub const fn value(&self) -> &serde_json::Value {
        &self.value
    }
}

/// Closed validated canonical replay payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalReplayPayload {
    Conversation(ConversationReplayPayload),
    TaskRun(TaskRunReplayPayload),
}

/// One validated canonical event without its transport cursor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalReplayEvent {
    pub(super) event_id: CanonicalId,
    pub(super) aggregate_kind: ReplayAggregateKind,
    pub(super) aggregate_id: CanonicalId,
    pub(super) sequence: u64,
    pub(super) timestamp_unix_micros: i64,
    pub(super) sensitivity: ReplaySensitivity,
    pub(super) event_type: String,
    pub(super) causation_event_id: Option<CanonicalId>,
    pub(super) correlation_id: CanonicalId,
    pub(super) correlation_kind: ReplayAggregateKind,
    pub(super) payload: CanonicalReplayPayload,
    pub(super) integrity_digest: [u8; 32],
    pub(super) canonical_bytes: Vec<u8>,
    pub(super) canonical_digest: [u8; 32],
}

impl CanonicalReplayEvent {
    #[must_use]
    pub const fn event_id(&self) -> CanonicalId {
        self.event_id
    }

    #[must_use]
    pub const fn aggregate_kind(&self) -> ReplayAggregateKind {
        self.aggregate_kind
    }

    #[must_use]
    pub const fn aggregate_id(&self) -> CanonicalId {
        self.aggregate_id
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn timestamp_unix_micros(&self) -> i64 {
        self.timestamp_unix_micros
    }

    #[must_use]
    pub const fn sensitivity(&self) -> ReplaySensitivity {
        self.sensitivity
    }

    #[must_use]
    pub fn event_type(&self) -> &str {
        &self.event_type
    }

    #[must_use]
    pub const fn causation_event_id(&self) -> Option<CanonicalId> {
        self.causation_event_id
    }

    #[must_use]
    pub const fn correlation_id(&self) -> CanonicalId {
        self.correlation_id
    }

    #[must_use]
    pub const fn correlation_kind(&self) -> ReplayAggregateKind {
        self.correlation_kind
    }

    #[must_use]
    pub const fn payload(&self) -> &CanonicalReplayPayload {
        &self.payload
    }

    #[must_use]
    pub const fn integrity_digest(&self) -> &[u8; 32] {
        &self.integrity_digest
    }

    #[must_use]
    pub const fn canonical_digest(&self) -> &[u8; 32] {
        &self.canonical_digest
    }
}
