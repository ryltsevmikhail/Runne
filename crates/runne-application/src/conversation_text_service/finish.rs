impl<R, I> ConversationTextService<R, I>
where
    R: ConversationRepository + ConversationTextRepository + EventStore,
    I: IdGenerator,
{
    /// Commits deterministic assistant output and completes the TaskRun.
    pub fn finish(
        &self,
        context: &ApplicationCommandContext,
        input: FinishConversationTextInput,
    ) -> Result<TextGenerationReceipt, ConversationTextServiceError> {
        let fingerprint = CommandFingerprint::for_generate_conversation_text(
            &input.original.conversation_id,
            input.original.expected_version,
            &input.original.text,
        );
        let scope = self.scope(context, input.original.conversation_id);
        let durable = match self
            .repository
            .lookup_text_generation_receipt(
                context.command_id,
                &context.idempotency_key,
                &scope,
                &fingerprint,
            )
            .map_err(map_commit)?
        {
            TextGenerationReceiptLookup::Miss => {
                return Err(ConversationTextServiceError::ReceiptMismatch);
            }
            TextGenerationReceiptLookup::Duplicate { stored_result } => stored_result,
        };
        validate_receipt(&durable, input.original.conversation_id)?;
        if matches!(
            durable.phase,
            TextGenerationPhase::Completed
                | TextGenerationPhase::Rejected
                | TextGenerationPhase::ProhibitedInputRejected
        ) {
            return Ok(durable);
        }
        if durable != input.started || durable.phase != TextGenerationPhase::Started {
            return Err(ConversationTextServiceError::ReceiptMismatch);
        }

        let conversation_stream = self
            .repository
            .load_conversation(durable.conversation_id)
            .map_err(map_conversation_load)?;
        validate_conversation_stream(&conversation_stream)?;
        if conversation_stream.current_version != durable.conversation_version {
            return Err(ConversationTextServiceError::Conflict);
        }
        let conversation = Conversation::replay(&conversation_stream.events)
            .map_err(|_| ConversationTextServiceError::StoredDataUnavailable)?;
        let taskrun_stream = self
            .repository
            .load_task_run(durable.taskrun_id)
            .map_err(|_| ConversationTextServiceError::StoredDataUnavailable)?;
        if taskrun_stream.current_version != durable.taskrun_version
            || taskrun_stream.last_event_id.is_none()
        {
            return Err(ConversationTextServiceError::StoredDataUnavailable);
        }
        let taskrun = TaskRun::replay(&taskrun_stream.events)
            .map_err(|_| ConversationTextServiceError::StoredDataUnavailable)?;

        let terminal_phase = match &input.completion {
            ConversationTextCompletion::AssistantText(_) => TextGenerationPhase::Completed,
            ConversationTextCompletion::ProhibitedInputRejected { .. } => {
                TextGenerationPhase::ProhibitedInputRejected
            }
            ConversationTextCompletion::Rejected { .. } => TextGenerationPhase::Rejected,
        };
        let (conversation_drafts, taskrun_drafts) = match input.completion {
            ConversationTextCompletion::AssistantText(assistant_text) => {
                let conversation_drafts = conversation
                    .decide(
                        runne_domain::command::ConversationCommand::AppendAssistantMessage {
                            message_id: durable.assistant_message_id,
                            taskrun_id: durable.taskrun_id,
                            attempt_id: durable.attempt_id,
                            text: assistant_text,
                        },
                    )
                    .map_err(ConversationTextServiceError::ConversationDomain)?;
                let taskrun_drafts = taskrun
                    .decide(TaskRunCommand::Complete {
                        result: TerminalResult::Success,
                    })
                    .map_err(|_| ConversationTextServiceError::TaskRunDomain)?;
                (conversation_drafts, taskrun_drafts)
            }
            ConversationTextCompletion::ProhibitedInputRejected { reason }
            | ConversationTextCompletion::Rejected { reason } => {
                let conversation_drafts = conversation
                    .decide(
                        runne_domain::command::ConversationCommand::FailGeneration {
                            taskrun_id: durable.taskrun_id,
                            attempt_id: durable.attempt_id,
                            reason,
                        },
                    )
                    .map_err(ConversationTextServiceError::ConversationDomain)?;
                let taskrun_drafts = taskrun
                    .decide(TaskRunCommand::FailGeneration { reason })
                    .map_err(|_| ConversationTextServiceError::TaskRunDomain)?;
                (conversation_drafts, taskrun_drafts)
            }
        };
        let event_ids = self
            .id_generator
            .next_event_ids(conversation_drafts.len() + taskrun_drafts.len())
            .map_err(ConversationTextServiceError::IdGeneration)?;
        let domain_context = domain_context(context);
        let split = conversation_drafts.len();
        let conversation_events = materialize_batch(
            conversation_drafts,
            &event_ids[..split],
            conversation_stream.last_event_id,
            &domain_context,
        )
        .map_err(|_| ConversationTextServiceError::MaterializationFailed)?;
        let taskrun_events = materialize_batch(
            taskrun_drafts,
            &event_ids[split..],
            taskrun_stream.last_event_id,
            &domain_context,
        )
        .map_err(|_| ConversationTextServiceError::MaterializationFailed)?;
        let terminal = TextGenerationReceipt {
            phase: terminal_phase,
            conversation_version: durable
                .conversation_version
                .checked_add(1)
                .ok_or(ConversationTextServiceError::StoredDataUnavailable)?,
            taskrun_version: durable
                .taskrun_version
                .checked_add(1)
                .ok_or(ConversationTextServiceError::StoredDataUnavailable)?,
            ..durable
        };
        let result = match terminal_phase {
            TextGenerationPhase::Completed => {
                self.repository
                    .finish_text_generation(FinishTextGenerationCommit {
                        command_id: context.command_id,
                        idempotency_key: context.idempotency_key.clone(),
                        idempotency_scope: scope,
                        command_fingerprint: fingerprint,
                        expected_conversation_version: input.started.conversation_version,
                        expected_taskrun_version: input.started.taskrun_version,
                        conversation_events,
                        taskrun_events,
                        receipt: terminal,
                    })
            }
            TextGenerationPhase::Rejected | TextGenerationPhase::ProhibitedInputRejected => self
                .repository
                .reject_text_generation(RejectTextGenerationCommit {
                    command_id: context.command_id,
                    idempotency_key: context.idempotency_key.clone(),
                    idempotency_scope: scope,
                    command_fingerprint: fingerprint,
                    expected_conversation_version: input.started.conversation_version,
                    expected_taskrun_version: input.started.taskrun_version,
                    conversation_events,
                    taskrun_events,
                    receipt: terminal,
                }),
            TextGenerationPhase::Started => unreachable!("started is not a terminal phase"),
        }
        .map_err(map_commit)?;
        commit_result(result, input.original.conversation_id)
    }

    fn scope(
        &self,
        context: &ApplicationCommandContext,
        conversation_id: runne_domain::id::ConversationId,
    ) -> IdempotencyScope {
        IdempotencyScope {
            runtime_authority_id: self.runtime_authority_id.clone(),
            principal_id: context.principal_id.clone(),
            operation: OperationTag::GenerateConversationText,
            aggregate_scope: AggregateScope::ExistingConversation { conversation_id },
        }
    }
}
