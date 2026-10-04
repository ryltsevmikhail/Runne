impl Conversation {
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
            ConversationEvent::GenerationSupersededUnknown {
                taskrun_id,
                attempt_id,
                ..
            } => {
                if self.state == ConversationState::Closed {
                    return Err(ConversationError::InvalidTransition {
                        from: self.state,
                        event: ConversationEventKind::GenerationSupersededUnknown,
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
