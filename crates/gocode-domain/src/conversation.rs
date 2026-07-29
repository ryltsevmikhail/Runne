//! Conversation aggregate — session lifecycle state machine.

use crate::event::{DomainEventDraft, EventEnvelope, Sensitivity};
use crate::id::{AggregateId, ConversationId, WorkspaceId};

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
    /// [`ConversationEvent::ConversationClosed`]
    ConversationClosed,
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
    /// The conversation was closed.
    ConversationClosed,
}

impl ConversationEvent {
    /// Return the discriminant kind for this event.
    pub fn kind(&self) -> ConversationEventKind {
        match self {
            Self::ConversationCreated { .. } => ConversationEventKind::ConversationCreated,
            Self::ConversationClosed => ConversationEventKind::ConversationClosed,
        }
    }
}

// ── ConversationError ─────────────────────────────────────────────────────

/// Closed, typed errors produced by the [`Conversation`] aggregate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConversationError {
    /// A close was requested for an already closed conversation.
    AlreadyClosed,
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
            Sensitivity::Public,
            ConversationEvent::ConversationCreated { workspace_id },
        )
    }

    /// Handle a command against an existing aggregate.
    pub fn decide(
        &self,
        command: ConversationCommand,
    ) -> Result<Vec<DomainEventDraft<ConversationEvent>>, ConversationError> {
        match command {
            ConversationCommand::Close if self.state == ConversationState::Closed => {
                Err(ConversationError::AlreadyClosed)
            }
            ConversationCommand::Close => {
                let aggregate_id = AggregateId::Conversation(self.id);
                Ok(vec![DomainEventDraft::new(
                    aggregate_id.clone(),
                    aggregate_id,
                    1,
                    Sensitivity::Public,
                    ConversationEvent::ConversationClosed,
                )])
            }
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
            ConversationEvent::ConversationClosed => {
                return Err(ConversationError::MissingCreationEvent);
            }
        };
        let mut aggregate = Self {
            id: conversation_id,
            workspace_id,
            state: ConversationState::Active,
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
            ConversationEvent::ConversationClosed if self.state == ConversationState::Closed => {
                Err(ConversationError::AlreadyClosed)
            }
            ConversationEvent::ConversationClosed => {
                self.state = ConversationState::Closed;
                Ok(())
            }
        }
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

    fn make_envelope(
        sequence: u64,
        payload: ConversationEvent,
        aggregate_id: AggregateId,
        correlation_id: AggregateId,
    ) -> EventEnvelope<ConversationEvent> {
        let draft = DomainEventDraft::new(
            aggregate_id,
            correlation_id,
            1,
            Sensitivity::Public,
            payload,
        );
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
    fn decide_close_emits_close_event_for_active_conversation() {
        let conversation = Conversation {
            id: conversation_id(),
            workspace_id: workspace_id(),
            state: ConversationState::Active,
        };

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
        let conversation = Conversation {
            id: conversation_id(),
            workspace_id: workspace_id(),
            state: ConversationState::Closed,
        };

        assert!(matches!(
            conversation.decide(ConversationCommand::Close),
            Err(ConversationError::AlreadyClosed)
        ));
    }

    #[test]
    fn apply_rejects_creation_after_create_without_mutation() {
        let mut conversation = Conversation {
            id: conversation_id(),
            workspace_id: workspace_id(),
            state: ConversationState::Active,
        };
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
        let mut conversation = Conversation {
            id: conversation_id(),
            workspace_id: workspace_id(),
            state: ConversationState::Closed,
        };
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
        let mut conversation = Conversation {
            id: conversation_id(),
            workspace_id: workspace_id(),
            state: ConversationState::Active,
        };
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
        let mut conversation = Conversation {
            id: conversation_id(),
            workspace_id: workspace_id(),
            state: ConversationState::Active,
        };
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
