// ── ConversationState ─────────────────────────────────────────────────────

/// All possible states of a [`Conversation`] aggregate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversationState {
    /// The conversation accepts commands.
    Active,
    /// The conversation is permanently closed.
    Closed,
}

// ── ConversationContextScope ──────────────────────────────────────────────

/// Durable delivery-context classification recorded when a Conversation is
/// created. The marker — not the absence of records — is what a delivery
/// trust gate reasons over: a missing marker is an unknown provenance, never
/// an implicit text-only grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversationContextScope {
    /// Project-scoped conversation: delivery requires a resolvable workspace
    /// bound to an explicitly trusted, currently admitted project.
    Workspace,
    /// Explicitly local, bounded text-only conversation: delivery is allowed
    /// without any workspace or project-trust resolution.
    TextOnly,
}

impl ConversationContextScope {
    /// Stable storage/wire representation of this scope.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Workspace => "workspace",
            Self::TextOnly => "text_only",
        }
    }

    /// Parses the stable storage/wire representation. Unknown values are
    /// rejected instead of being widened into a permitted scope.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "workspace" => Some(Self::Workspace),
            "text_only" => Some(Self::TextOnly),
            _ => None,
        }
    }
}

// ── ConversationEventKind ─────────────────────────────────────────────────

/// Discriminant-only representation of a [`ConversationEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversationEventKind {
    /// [`ConversationEvent::ConversationCreated`]
    ConversationCreated,
    /// [`ConversationEvent::UserMessageAppended`]
    UserMessageAppended,
    /// [`ConversationEvent::AssistantMessageAppended`]
    AssistantMessageAppended,
    /// [`ConversationEvent::GenerationFailed`]
    GenerationFailed,
    /// [`ConversationEvent::ConversationClosed`]
    ConversationClosed,
}

/// Closed, non-sensitive reason for releasing an active generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerationFailureReason {
    /// Provider input or output contained registered prohibited material.
    ProviderOutputRejected,
}

impl GenerationFailureReason {
    /// Stable terminal code persisted on the coordinating TaskRun.
    #[must_use]
    pub const fn as_code(self) -> &'static str {
        match self {
            Self::ProviderOutputRejected => "provider_output_rejected",
        }
    }
}

// ── ConversationEvent ─────────────────────────────────────────────────────

/// All events emitted by the [`Conversation`] aggregate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationEvent {
    /// The conversation was created in a workspace.
    ConversationCreated {
        /// The workspace that owns the conversation.
        workspace_id: WorkspaceId,
    },
    /// A user message was appended and bound to one exact execution attempt.
    UserMessageAppended {
        /// Message identity.
        message_id: MessageId,
        /// Coordinating TaskRun.
        taskrun_id: TaskRunId,
        /// Exact running attempt.
        attempt_id: AttemptId,
        /// Validated bounded text.
        text: MessageText,
    },
    /// The active execution produced its assistant message.
    AssistantMessageAppended {
        /// Message identity.
        message_id: MessageId,
        /// Coordinating TaskRun.
        taskrun_id: TaskRunId,
        /// Exact running attempt.
        attempt_id: AttemptId,
        /// Validated bounded text.
        text: MessageText,
    },
    /// The active generation was rejected without an assistant message.
    GenerationFailed {
        /// Coordinating TaskRun.
        taskrun_id: TaskRunId,
        /// Exact active attempt.
        attempt_id: AttemptId,
        /// Closed, non-sensitive terminal reason.
        reason: GenerationFailureReason,
    },
    /// The conversation was closed.
    ConversationClosed,
}

impl ConversationEvent {
    /// Return the discriminant kind for this event.
    pub fn kind(&self) -> ConversationEventKind {
        match self {
            Self::ConversationCreated { .. } => ConversationEventKind::ConversationCreated,
            Self::UserMessageAppended { .. } => ConversationEventKind::UserMessageAppended,
            Self::AssistantMessageAppended { .. } => {
                ConversationEventKind::AssistantMessageAppended
            }
            Self::GenerationFailed { .. } => ConversationEventKind::GenerationFailed,
            Self::ConversationClosed => ConversationEventKind::ConversationClosed,
        }
    }

    /// Deterministic sensitivity classification for this event type.
    #[must_use]
    pub const fn sensitivity(&self) -> Sensitivity {
        match self {
            Self::ConversationCreated { .. }
            | Self::GenerationFailed { .. }
            | Self::ConversationClosed => Sensitivity::Public,
            Self::UserMessageAppended { .. } | Self::AssistantMessageAppended { .. } => {
                Sensitivity::Sensitive
            }
        }
    }
}

// ── ConversationError ─────────────────────────────────────────────────────

/// Closed, typed errors produced by the [`Conversation`] aggregate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationError {
    /// A close was requested for an already closed conversation.
    AlreadyClosed,
    /// A user message cannot start while another generation is active.
    GenerationAlreadyActive {
        /// TaskRun already bound to the active generation.
        taskrun_id: TaskRunId,
    },
    /// An assistant message has no matching active generation.
    NoActiveGeneration,
    /// Assistant output referenced a different TaskRun or attempt.
    GenerationMismatch,
    /// A message identity was already used in this Conversation.
    DuplicateMessageId {
        /// Reused message identity.
        message_id: MessageId,
    },
    /// Stored sensitivity did not match the event's deterministic class.
    SensitivityMismatch {
        /// Expected event classification.
        expected: Sensitivity,
        /// Stored classification.
        actual: Sensitivity,
    },
    /// An event is invalid from the aggregate's current state.
    InvalidTransition {
        /// The aggregate's current state.
        from: ConversationState,
        /// The rejected event kind.
        event: ConversationEventKind,
    },
    /// An event belongs to a different aggregate or correlation stream.
    AggregateIdMismatch {
        /// The expected conversation aggregate ID.
        expected: AggregateId,
        /// The ID present on the event.
        actual: AggregateId,
    },
    /// Replay did not begin with a creation event.
    MissingCreationEvent,
    /// Replay included more than one creation event.
    DuplicateCreationEvent {
        /// The conversation with multiple creation events.
        conversation_id: ConversationId,
    },
    /// Replay found a non-contiguous sequence number.
    SequenceGap {
        /// The expected sequence number.
        expected: u64,
        /// The actual sequence number.
        actual: u64,
    },
    /// Replay's first event did not have sequence number one.
    InvalidInitialSequence {
        /// The expected initial sequence number.
        expected: u64,
        /// The actual initial sequence number.
        actual: u64,
    },
}
