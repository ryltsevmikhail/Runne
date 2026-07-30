//! Conversation aggregate — session lifecycle state machine.

use crate::event::{DomainEventDraft, EventEnvelope, Sensitivity};
use crate::id::{AggregateId, AttemptId, ConversationId, MessageId, TaskRunId, WorkspaceId};
use crate::message::{ConversationMessage, MessageRole, MessageText};

pub use crate::command::ConversationCommand;

// ── ConversationState ─────────────────────────────────────────────────────

/// All possible states of a [`Conversation`] aggregate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConversationState {
    /// The conversation accepts commands.
    Active,
    /// The conversation is permanently closed.
    Closed,
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

// ── Conversation aggregate ────────────────────────────────────────────────

/// Conversation aggregate root — tracks session lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conversation {
    /// The aggregate identity.
    pub id: ConversationId,
    /// The workspace that owns the conversation.
    pub workspace_id: WorkspaceId,
    /// The current lifecycle state.
    pub state: ConversationState,
    messages: Vec<ConversationMessage>,
    active_generation: Option<ActiveTextGeneration>,
}

/// Active durable user-to-assistant execution binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveTextGeneration {
    /// User message awaiting an assistant response.
    pub user_message_id: MessageId,
    /// Coordinating TaskRun.
    pub taskrun_id: TaskRunId,
    /// Exact running attempt.
    pub attempt_id: AttemptId,
}

impl Conversation {
    /// Handle creation — produces the initial event.
    pub fn decide_create(
        conversation_id: ConversationId,
        workspace_id: WorkspaceId,
    ) -> DomainEventDraft<ConversationEvent> {
        let aggregate_id = AggregateId::Conversation(conversation_id);
        DomainEventDraft::new(
            aggregate_id.clone(),
            aggregate_id,
            1,
            ConversationEvent::ConversationCreated { workspace_id }.sensitivity(),
            ConversationEvent::ConversationCreated { workspace_id },
        )
    }

    /// Returns the durable message timeline.
    #[must_use]
    pub fn messages(&self) -> &[ConversationMessage] {
        &self.messages
    }

    /// Returns the currently active text generation, if any.
    #[must_use]
    pub const fn active_generation(&self) -> Option<&ActiveTextGeneration> {
        self.active_generation.as_ref()
    }

    /// Handle a command against an existing aggregate.
    pub fn decide(
        &self,
        command: ConversationCommand,
    ) -> Result<Vec<DomainEventDraft<ConversationEvent>>, ConversationError> {
        if self.state == ConversationState::Closed {
            return match command {
                ConversationCommand::Close => Err(ConversationError::AlreadyClosed),
                ConversationCommand::AppendUserMessage { .. } => {
                    Err(ConversationError::InvalidTransition {
                        from: self.state,
                        event: ConversationEventKind::UserMessageAppended,
                    })
                }
                ConversationCommand::AppendAssistantMessage { .. } => {
                    Err(ConversationError::InvalidTransition {
                        from: self.state,
                        event: ConversationEventKind::AssistantMessageAppended,
                    })
                }
                ConversationCommand::FailGeneration { .. } => {
                    Err(ConversationError::InvalidTransition {
                        from: self.state,
                        event: ConversationEventKind::GenerationFailed,
                    })
                }
            };
        }
        let aggregate_id = AggregateId::Conversation(self.id);
        let draft = |payload: ConversationEvent| {
            DomainEventDraft::new(
                aggregate_id.clone(),
                aggregate_id.clone(),
                1,
                payload.sensitivity(),
                payload,
            )
        };
        match command {
            ConversationCommand::AppendUserMessage {
                message_id,
                taskrun_id,
                attempt_id,
                text,
            } => {
                if let Some(active) = self.active_generation {
                    return Err(ConversationError::GenerationAlreadyActive {
                        taskrun_id: active.taskrun_id,
                    });
                }
                self.require_unique_message_id(message_id)?;
                Ok(vec![draft(ConversationEvent::UserMessageAppended {
                    message_id,
                    taskrun_id,
                    attempt_id,
                    text,
                })])
            }
            ConversationCommand::AppendAssistantMessage {
                message_id,
                taskrun_id,
                attempt_id,
                text,
            } => {
                let active = self
                    .active_generation
                    .ok_or(ConversationError::NoActiveGeneration)?;
                if active.taskrun_id != taskrun_id || active.attempt_id != attempt_id {
                    return Err(ConversationError::GenerationMismatch);
                }
                self.require_unique_message_id(message_id)?;
                Ok(vec![draft(ConversationEvent::AssistantMessageAppended {
                    message_id,
                    taskrun_id,
                    attempt_id,
                    text,
                })])
            }
            ConversationCommand::FailGeneration {
                taskrun_id,
                attempt_id,
                reason,
            } => {
                let active = self
                    .active_generation
                    .ok_or(ConversationError::NoActiveGeneration)?;
                if active.taskrun_id != taskrun_id || active.attempt_id != attempt_id {
                    return Err(ConversationError::GenerationMismatch);
                }
                Ok(vec![draft(ConversationEvent::GenerationFailed {
                    taskrun_id,
                    attempt_id,
                    reason,
                })])
            }
            ConversationCommand::Close => Ok(vec![draft(ConversationEvent::ConversationClosed)]),
        }
    }

    /// Apply a committed event to this aggregate, mutating state.
    pub fn apply(
        &mut self,
        event: &EventEnvelope<ConversationEvent>,
    ) -> Result<(), ConversationError> {
        let expected = AggregateId::Conversation(self.id);
        if *event.aggregate_id() != expected {
            return Err(ConversationError::AggregateIdMismatch {
                expected: expected.clone(),
                actual: event.aggregate_id().clone(),
            });
        }
        if *event.correlation_id() != expected {
            return Err(ConversationError::AggregateIdMismatch {
                expected,
                actual: event.correlation_id().clone(),
            });
        }
        if *event.sensitivity() != event.payload().sensitivity() {
            return Err(ConversationError::SensitivityMismatch {
                expected: event.payload().sensitivity(),
                actual: *event.sensitivity(),
            });
        }

        self.apply_payload(event.payload())
    }

    /// Replay a sequence of committed events to reconstruct an aggregate.
    pub fn replay(events: &[EventEnvelope<ConversationEvent>]) -> Result<Self, ConversationError> {
        if events.is_empty()
            || events[0].payload().kind() != ConversationEventKind::ConversationCreated
        {
            return Err(ConversationError::MissingCreationEvent);
        }

        let first = &events[0];
        if *first.sensitivity() != first.payload().sensitivity() {
            return Err(ConversationError::SensitivityMismatch {
                expected: first.payload().sensitivity(),
                actual: *first.sensitivity(),
            });
        }
        if first.sequence() != 1 {
            return Err(ConversationError::InvalidInitialSequence {
                expected: 1,
                actual: first.sequence(),
            });
        }

        let conversation_id = match first.aggregate_id() {
            AggregateId::Conversation(id) => *id,
            _ => {
                return Err(ConversationError::AggregateIdMismatch {
                    expected: first.correlation_id().clone(),
                    actual: first.aggregate_id().clone(),
                });
            }
        };
        let expected = AggregateId::Conversation(conversation_id);
        if *first.correlation_id() != expected {
            return Err(ConversationError::AggregateIdMismatch {
                expected,
                actual: first.correlation_id().clone(),
            });
        }

        let workspace_id = match first.payload() {
            ConversationEvent::ConversationCreated { workspace_id } => *workspace_id,
            ConversationEvent::UserMessageAppended { .. }
            | ConversationEvent::AssistantMessageAppended { .. }
            | ConversationEvent::GenerationFailed { .. }
            | ConversationEvent::ConversationClosed => {
                return Err(ConversationError::MissingCreationEvent);
            }
        };
        let mut aggregate = Self {
            id: conversation_id,
            workspace_id,
            state: ConversationState::Active,
            messages: Vec::new(),
            active_generation: None,
        };

        for (expected_sequence, event) in (2_u64..).zip(&events[1..]) {
            if event.sequence() != expected_sequence {
                return Err(ConversationError::SequenceGap {
                    expected: expected_sequence,
                    actual: event.sequence(),
                });
            }
            if *event.aggregate_id() != expected {
                return Err(ConversationError::AggregateIdMismatch {
                    expected: expected.clone(),
                    actual: event.aggregate_id().clone(),
                });
            }
            if *event.correlation_id() != expected {
                return Err(ConversationError::AggregateIdMismatch {
                    expected: expected.clone(),
                    actual: event.correlation_id().clone(),
                });
            }

            if event.payload().kind() == ConversationEventKind::ConversationCreated {
                return Err(ConversationError::DuplicateCreationEvent { conversation_id });
            }
            if *event.sensitivity() != event.payload().sensitivity() {
                return Err(ConversationError::SensitivityMismatch {
                    expected: event.payload().sensitivity(),
                    actual: *event.sensitivity(),
                });
            }
            aggregate.apply_payload(event.payload())?;
        }

        Ok(aggregate)
    }

    /// Apply an event payload after event identity has been verified.
    fn apply_payload(&mut self, payload: &ConversationEvent) -> Result<(), ConversationError> {
        match payload {
            ConversationEvent::ConversationCreated { .. } => {
                Err(ConversationError::InvalidTransition {
                    from: self.state,
                    event: ConversationEventKind::ConversationCreated,
                })
            }
            ConversationEvent::UserMessageAppended {
                message_id,
                taskrun_id,
                attempt_id,
                text,
            } => {
                if self.state == ConversationState::Closed {
                    return Err(ConversationError::InvalidTransition {
                        from: self.state,
                        event: ConversationEventKind::UserMessageAppended,
                    });
                }
                if let Some(active) = self.active_generation {
                    return Err(ConversationError::GenerationAlreadyActive {
                        taskrun_id: active.taskrun_id,
                    });
                }
                self.require_unique_message_id(*message_id)?;
                self.messages.push(ConversationMessage {
                    message_id: *message_id,
                    role: MessageRole::User,
                    taskrun_id: *taskrun_id,
                    attempt_id: *attempt_id,
                    text: text.clone(),
                });
                self.active_generation = Some(ActiveTextGeneration {
                    user_message_id: *message_id,
                    taskrun_id: *taskrun_id,
                    attempt_id: *attempt_id,
                });
                Ok(())
            }
            ConversationEvent::AssistantMessageAppended {
                message_id,
                taskrun_id,
                attempt_id,
                text,
            } => {
                if self.state == ConversationState::Closed {
                    return Err(ConversationError::InvalidTransition {
                        from: self.state,
                        event: ConversationEventKind::AssistantMessageAppended,
                    });
                }
                let active = self
                    .active_generation
                    .ok_or(ConversationError::NoActiveGeneration)?;
                if active.taskrun_id != *taskrun_id || active.attempt_id != *attempt_id {
                    return Err(ConversationError::GenerationMismatch);
                }
                self.require_unique_message_id(*message_id)?;
                self.messages.push(ConversationMessage {
                    message_id: *message_id,
                    role: MessageRole::Assistant,
                    taskrun_id: *taskrun_id,
                    attempt_id: *attempt_id,
                    text: text.clone(),
                });
                self.active_generation = None;
                Ok(())
            }
            ConversationEvent::GenerationFailed {
                taskrun_id,
                attempt_id,
                ..
            } => {
                if self.state == ConversationState::Closed {
                    return Err(ConversationError::InvalidTransition {
                        from: self.state,
                        event: ConversationEventKind::GenerationFailed,
                    });
                }
                let active = self
                    .active_generation
                    .ok_or(ConversationError::NoActiveGeneration)?;
                if active.taskrun_id != *taskrun_id || active.attempt_id != *attempt_id {
                    return Err(ConversationError::GenerationMismatch);
                }
                self.active_generation = None;
                Ok(())
            }
            ConversationEvent::ConversationClosed if self.state == ConversationState::Closed => {
                Err(ConversationError::AlreadyClosed)
            }
            ConversationEvent::ConversationClosed => {
                self.state = ConversationState::Closed;
                Ok(())
            }
        }
    }

    fn require_unique_message_id(&self, message_id: MessageId) -> Result<(), ConversationError> {
        if self
            .messages
            .iter()
            .any(|message| message.message_id == message_id)
        {
            return Err(ConversationError::DuplicateMessageId { message_id });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{Actor, CommandContext, materialize_batch};
    use crate::id::{IdempotencyKey, IntegrityDigest, TaskRunId};
    use crate::timestamp::Timestamp;

    const CONVERSATION_ID: &str = "018f2e3a-7000-7000-8000-000000000000";
    const WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-000000000001";
    const TASKRUN_ID: &str = "018f2e3a-7000-7000-8000-000000000002";
    const OTHER_WORKSPACE_ID: &str = "018f2e3a-7000-7000-8000-000000000003";
    const ATTEMPT_ID: &str = "018f2e3a-7000-7000-8000-000000000004";
    const USER_MESSAGE_ID: &str = "018f2e3a-7000-7000-8000-000000000005";
    const ASSISTANT_MESSAGE_ID: &str = "018f2e3a-7000-7000-8000-000000000006";

    fn make_envelope(
        sequence: u64,
        payload: ConversationEvent,
        aggregate_id: AggregateId,
        correlation_id: AggregateId,
    ) -> EventEnvelope<ConversationEvent> {
        let sensitivity = payload.sensitivity();
        let draft = DomainEventDraft::new(aggregate_id, correlation_id, 1, sensitivity, payload);
        let context = CommandContext {
            command_id: CONVERSATION_ID.parse().expect("valid UUIDv7"),
            idempotency_key: IdempotencyKey::new("test").expect("valid idempotency key"),
            actor: Actor::new("test").expect("valid actor"),
        };
        let event_ids = &[CONVERSATION_ID.parse().expect("valid UUIDv7")];
        materialize_batch(vec![draft], event_ids, None, &context)
            .expect("one materialized event")
            .pop()
            .expect("one uncommitted event")
            .into_envelope(
                sequence,
                Timestamp::from_unix_micros(1_000),
                IntegrityDigest::from_bytes([0; 32]),
            )
    }

    fn conversation_id() -> ConversationId {
        CONVERSATION_ID.parse().expect("valid UUIDv7")
    }

    fn workspace_id() -> WorkspaceId {
        WORKSPACE_ID.parse().expect("valid UUIDv7")
    }

    fn other_workspace_id() -> WorkspaceId {
        OTHER_WORKSPACE_ID.parse().expect("valid UUIDv7")
    }

    fn conversation_aggregate_id() -> AggregateId {
        AggregateId::Conversation(conversation_id())
    }

    fn taskrun_id() -> TaskRunId {
        TASKRUN_ID.parse().expect("valid UUIDv7")
    }

    fn attempt_id() -> AttemptId {
        ATTEMPT_ID.parse().expect("valid UUIDv7")
    }

    fn user_message_id() -> MessageId {
        USER_MESSAGE_ID.parse().expect("valid UUIDv7")
    }

    fn assistant_message_id() -> MessageId {
        ASSISTANT_MESSAGE_ID.parse().expect("valid UUIDv7")
    }

    fn conversation(state: ConversationState) -> Conversation {
        Conversation {
            id: conversation_id(),
            workspace_id: workspace_id(),
            state,
            messages: Vec::new(),
            active_generation: None,
        }
    }

    #[test]
    fn decide_create_sets_conversation_identity_for_aggregate_and_correlation() {
        let draft = Conversation::decide_create(conversation_id(), workspace_id());

        assert_eq!(draft.aggregate_id(), &conversation_aggregate_id());
        assert_eq!(draft.correlation_id(), &conversation_aggregate_id());
        assert_eq!(
            draft.payload(),
            &ConversationEvent::ConversationCreated {
                workspace_id: workspace_id(),
            }
        );
    }

    #[test]
    fn replay_created_conversation_is_active() {
        let events = [make_envelope(
            1,
            ConversationEvent::ConversationCreated {
                workspace_id: workspace_id(),
            },
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        )];

        let conversation = Conversation::replay(&events).expect("valid conversation stream");

        assert_eq!(conversation.id, conversation_id());
        assert_eq!(conversation.workspace_id, workspace_id());
        assert_eq!(conversation.state, ConversationState::Active);
    }

    #[test]
    fn replay_close_transitions_to_closed() {
        let events = [
            make_envelope(
                1,
                ConversationEvent::ConversationCreated {
                    workspace_id: workspace_id(),
                },
                conversation_aggregate_id(),
                conversation_aggregate_id(),
            ),
            make_envelope(
                2,
                ConversationEvent::ConversationClosed,
                conversation_aggregate_id(),
                conversation_aggregate_id(),
            ),
        ];

        let conversation = Conversation::replay(&events).expect("valid conversation stream");

        assert_eq!(conversation.state, ConversationState::Closed);
    }

    #[test]
    fn user_and_assistant_messages_are_sensitive_and_replay_as_one_exchange() {
        let created = make_envelope(
            1,
            ConversationEvent::ConversationCreated {
                workspace_id: workspace_id(),
            },
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        );
        let aggregate = Conversation::replay(std::slice::from_ref(&created)).unwrap();
        let user_draft = aggregate
            .decide(ConversationCommand::AppendUserMessage {
                message_id: user_message_id(),
                taskrun_id: taskrun_id(),
                attempt_id: attempt_id(),
                text: MessageText::new("hello").unwrap(),
            })
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(user_draft.sensitivity(), &Sensitivity::Sensitive);
        let user = make_envelope(
            2,
            user_draft.into_payload(),
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        );
        let aggregate = Conversation::replay(&[created.clone(), user.clone()]).unwrap();
        assert_eq!(
            aggregate.active_generation(),
            Some(&ActiveTextGeneration {
                user_message_id: user_message_id(),
                taskrun_id: taskrun_id(),
                attempt_id: attempt_id(),
            })
        );

        let assistant_draft = aggregate
            .decide(ConversationCommand::AppendAssistantMessage {
                message_id: assistant_message_id(),
                taskrun_id: taskrun_id(),
                attempt_id: attempt_id(),
                text: MessageText::new("world").unwrap(),
            })
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(assistant_draft.sensitivity(), &Sensitivity::Sensitive);
        let assistant = make_envelope(
            3,
            assistant_draft.into_payload(),
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        );

        let replayed = Conversation::replay(&[created, user, assistant]).unwrap();
        assert_eq!(replayed.active_generation(), None);
        assert_eq!(replayed.messages().len(), 2);
        assert_eq!(replayed.messages()[0].role, MessageRole::User);
        assert_eq!(replayed.messages()[0].text.as_str(), "hello");
        assert_eq!(replayed.messages()[1].role, MessageRole::Assistant);
        assert_eq!(replayed.messages()[1].text.as_str(), "world");
    }

    #[test]
    fn assistant_message_must_match_the_active_taskrun_and_attempt() {
        let events = [
            make_envelope(
                1,
                ConversationEvent::ConversationCreated {
                    workspace_id: workspace_id(),
                },
                conversation_aggregate_id(),
                conversation_aggregate_id(),
            ),
            make_envelope(
                2,
                ConversationEvent::UserMessageAppended {
                    message_id: user_message_id(),
                    taskrun_id: taskrun_id(),
                    attempt_id: attempt_id(),
                    text: MessageText::new("hello").unwrap(),
                },
                conversation_aggregate_id(),
                conversation_aggregate_id(),
            ),
        ];
        let aggregate = Conversation::replay(&events).unwrap();

        assert!(matches!(
            aggregate.decide(ConversationCommand::AppendAssistantMessage {
                message_id: assistant_message_id(),
                taskrun_id: "018f2e3a-7000-7000-8000-000000000007".parse().unwrap(),
                attempt_id: attempt_id(),
                text: MessageText::new("wrong").unwrap(),
            }),
            Err(ConversationError::GenerationMismatch)
        ));
        assert_eq!(aggregate.messages().len(), 1);
    }

    #[test]
    fn provider_output_rejection_releases_generation_without_assistant_message() {
        let created = make_envelope(
            1,
            ConversationEvent::ConversationCreated {
                workspace_id: workspace_id(),
            },
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        );
        let user = make_envelope(
            2,
            ConversationEvent::UserMessageAppended {
                message_id: user_message_id(),
                taskrun_id: taskrun_id(),
                attempt_id: attempt_id(),
                text: MessageText::new("hello").unwrap(),
            },
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        );
        let aggregate = Conversation::replay(&[created.clone(), user.clone()]).unwrap();

        let rejection = aggregate
            .decide(ConversationCommand::FailGeneration {
                taskrun_id: taskrun_id(),
                attempt_id: attempt_id(),
                reason: GenerationFailureReason::ProviderOutputRejected,
            })
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            rejection.payload(),
            &ConversationEvent::GenerationFailed {
                taskrun_id: taskrun_id(),
                attempt_id: attempt_id(),
                reason: GenerationFailureReason::ProviderOutputRejected,
            }
        );
        assert_eq!(rejection.sensitivity(), &Sensitivity::Public);
        let rejection = make_envelope(
            3,
            rejection.into_payload(),
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        );

        let replayed = Conversation::replay(&[created, user, rejection]).unwrap();
        assert_eq!(replayed.active_generation(), None);
        assert_eq!(replayed.messages().len(), 1);
        assert_eq!(replayed.messages()[0].role, MessageRole::User);
    }

    #[test]
    fn decide_close_emits_close_event_for_active_conversation() {
        let conversation = conversation(ConversationState::Active);

        let events = conversation
            .decide(ConversationCommand::Close)
            .expect("active conversation can close");

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].payload(), &ConversationEvent::ConversationClosed);
        assert_eq!(events[0].aggregate_id(), &conversation_aggregate_id());
        assert_eq!(events[0].correlation_id(), &conversation_aggregate_id());
    }

    #[test]
    fn decide_rejects_closing_closed_conversation() {
        let conversation = conversation(ConversationState::Closed);

        assert!(matches!(
            conversation.decide(ConversationCommand::Close),
            Err(ConversationError::AlreadyClosed)
        ));
    }

    #[test]
    fn apply_rejects_creation_after_create_without_mutation() {
        let mut conversation = conversation(ConversationState::Active);
        let event = make_envelope(
            2,
            ConversationEvent::ConversationCreated {
                workspace_id: other_workspace_id(),
            },
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        );

        assert_eq!(
            conversation.apply(&event),
            Err(ConversationError::InvalidTransition {
                from: ConversationState::Active,
                event: ConversationEventKind::ConversationCreated,
            })
        );
        assert_eq!(conversation.state, ConversationState::Active);
        assert_eq!(conversation.workspace_id, workspace_id());
    }

    #[test]
    fn apply_rejects_creation_after_close_without_mutation() {
        let mut conversation = conversation(ConversationState::Closed);
        let event = make_envelope(
            3,
            ConversationEvent::ConversationCreated {
                workspace_id: other_workspace_id(),
            },
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        );

        assert_eq!(
            conversation.apply(&event),
            Err(ConversationError::InvalidTransition {
                from: ConversationState::Closed,
                event: ConversationEventKind::ConversationCreated,
            })
        );
        assert_eq!(conversation.state, ConversationState::Closed);
        assert_eq!(conversation.workspace_id, workspace_id());
    }

    #[test]
    fn apply_rejects_non_conversation_aggregate_id() {
        let mut conversation = conversation(ConversationState::Active);
        let taskrun_id: TaskRunId = TASKRUN_ID.parse().expect("valid UUIDv7");
        let event = make_envelope(
            2,
            ConversationEvent::ConversationClosed,
            AggregateId::TaskRun(taskrun_id),
            conversation_aggregate_id(),
        );

        assert_eq!(
            conversation.apply(&event),
            Err(ConversationError::AggregateIdMismatch {
                expected: conversation_aggregate_id(),
                actual: AggregateId::TaskRun(taskrun_id),
            })
        );
        assert_eq!(conversation.state, ConversationState::Active);
    }

    #[test]
    fn apply_rejects_non_conversation_correlation_id() {
        let mut conversation = conversation(ConversationState::Active);
        let taskrun_id: TaskRunId = TASKRUN_ID.parse().expect("valid UUIDv7");
        let event = make_envelope(
            2,
            ConversationEvent::ConversationClosed,
            conversation_aggregate_id(),
            AggregateId::TaskRun(taskrun_id),
        );

        assert_eq!(
            conversation.apply(&event),
            Err(ConversationError::AggregateIdMismatch {
                expected: conversation_aggregate_id(),
                actual: AggregateId::TaskRun(taskrun_id),
            })
        );
        assert_eq!(conversation.state, ConversationState::Active);
    }

    #[test]
    fn replay_rejects_non_conversation_aggregate_id() {
        let taskrun_id: TaskRunId = TASKRUN_ID.parse().expect("valid UUIDv7");
        let event = make_envelope(
            1,
            ConversationEvent::ConversationCreated {
                workspace_id: workspace_id(),
            },
            AggregateId::TaskRun(taskrun_id),
            conversation_aggregate_id(),
        );

        assert!(matches!(
            Conversation::replay(&[event]),
            Err(ConversationError::AggregateIdMismatch { .. })
        ));
    }

    #[test]
    fn replay_rejects_non_conversation_correlation_id() {
        let taskrun_id: TaskRunId = TASKRUN_ID.parse().expect("valid UUIDv7");
        let event = make_envelope(
            1,
            ConversationEvent::ConversationCreated {
                workspace_id: workspace_id(),
            },
            conversation_aggregate_id(),
            AggregateId::TaskRun(taskrun_id),
        );

        assert_eq!(
            Conversation::replay(&[event]),
            Err(ConversationError::AggregateIdMismatch {
                expected: conversation_aggregate_id(),
                actual: AggregateId::TaskRun(taskrun_id),
            })
        );
    }

    #[test]
    fn replay_rejects_empty_stream_and_sequence_errors() {
        assert_eq!(
            Conversation::replay(&[]),
            Err(ConversationError::MissingCreationEvent)
        );

        let event = make_envelope(
            2,
            ConversationEvent::ConversationCreated {
                workspace_id: workspace_id(),
            },
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        );
        assert_eq!(
            Conversation::replay(&[event]),
            Err(ConversationError::InvalidInitialSequence {
                expected: 1,
                actual: 2,
            })
        );
    }

    #[test]
    fn replay_rejects_sequence_gap_and_duplicate_creation() {
        let created = make_envelope(
            1,
            ConversationEvent::ConversationCreated {
                workspace_id: workspace_id(),
            },
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        );
        let gap = make_envelope(
            3,
            ConversationEvent::ConversationClosed,
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        );
        assert_eq!(
            Conversation::replay(&[created.clone(), gap]),
            Err(ConversationError::SequenceGap {
                expected: 2,
                actual: 3,
            })
        );

        let duplicate = make_envelope(
            2,
            ConversationEvent::ConversationCreated {
                workspace_id: workspace_id(),
            },
            conversation_aggregate_id(),
            conversation_aggregate_id(),
        );
        assert_eq!(
            Conversation::replay(&[created, duplicate]),
            Err(ConversationError::DuplicateCreationEvent {
                conversation_id: conversation_id(),
            })
        );
    }
}
