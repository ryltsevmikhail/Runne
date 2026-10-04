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
                ConversationCommand::SupersedeGenerationUnknown { .. } => {
                    Err(ConversationError::InvalidTransition {
                        from: self.state,
                        event: ConversationEventKind::GenerationSupersededUnknown,
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
            ConversationCommand::SupersedeGenerationUnknown {
                taskrun_id,
                attempt_id,
                successor_taskrun_id,
                acknowledgement_digest,
            } => {
                let active = self
                    .active_generation
                    .ok_or(ConversationError::NoActiveGeneration)?;
                if active.taskrun_id != taskrun_id || active.attempt_id != attempt_id {
                    return Err(ConversationError::GenerationMismatch);
                }
                Ok(vec![draft(ConversationEvent::GenerationSupersededUnknown {
                    taskrun_id,
                    attempt_id,
                    successor_taskrun_id,
                    acknowledgement_digest,
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
            | ConversationEvent::GenerationSupersededUnknown { .. }
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

}
