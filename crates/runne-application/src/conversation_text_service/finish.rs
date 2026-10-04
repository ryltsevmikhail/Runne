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
        let terminal_cancellation_input = matches!(
            &input.completion,
            ConversationTextCompletion::TerminalSettledCancellation { .. }
                | ConversationTextCompletion::UnknownJournalSettledCancellation { .. }
                | ConversationTextCompletion::RemoteArtifactSettledCancellation { .. }
                | ConversationTextCompletion::PreEffectRejectedCancellation { .. }
                | ConversationTextCompletion::NoProviderAdmissionCancellation { .. }
        );
        if let Some(receipt) = self.replay_remote_artifact_cancellation(
            context,
            &input,
            &durable,
            &scope,
            &fingerprint,
        )? {
            return Ok(receipt);
        }
        if terminal_cancellation_input {
            validate_terminal_cancellation_receipt(&durable, input.original.conversation_id)?;
        } else {
            validate_receipt(&durable, input.original.conversation_id)?;
        }
        validate_no_admission_replay(&self.repository, &durable, &input.completion)?;
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
        let CancellationFacts {
            terminal: terminal_cancellation,
            unknown_terminal: unknown_terminal_cancellation,
            remote_artifact: remote_artifact_cancellation,
            pre_effect: pre_effect_cancellation,
            no_admission: no_admission_cancellation,
            taskrun_version: cancellation_taskrun_version,
        } = CancellationFacts::from_completion(&input.completion);
        let expected_taskrun_head = cancellation_taskrun_version.unwrap_or(durable.taskrun_version);
        if taskrun_stream.current_version != expected_taskrun_head
            || taskrun_stream.last_event_id.is_none()
        {
            return Err(ConversationTextServiceError::StoredDataUnavailable);
        }
        let taskrun = TaskRun::replay(&taskrun_stream.events)
            .map_err(|_| ConversationTextServiceError::StoredDataUnavailable)?;

        let (terminal_phase, conversation_drafts, taskrun_drafts) =
            terminal_drafts(input.completion, &durable, &conversation, &taskrun)?;
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
        let terminal_taskrun_version = expected_taskrun_head
            .checked_add(1)
            .ok_or(ConversationTextServiceError::StoredDataUnavailable)?;
        let terminal = TextGenerationReceipt {
            phase: terminal_phase,
            conversation_version: durable
                .conversation_version
                .checked_add(1)
                .ok_or(ConversationTextServiceError::StoredDataUnavailable)?,
            taskrun_version: terminal_taskrun_version,
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
            TextGenerationPhase::Rejected if terminal_cancellation.is_some() => self
                .repository
                .reject_text_generation_after_terminal_cancellation(
                    RejectTextGenerationAfterTerminalCancellationCommit {
                        command_id: context.command_id,
                        idempotency_key: context.idempotency_key.clone(),
                        idempotency_scope: scope,
                        command_fingerprint: fingerprint,
                        expected_conversation_version: input.started.conversation_version,
                        expected_started_taskrun_version: input.started.taskrun_version,
                        evidence: terminal_cancellation
                            .ok_or(ConversationTextServiceError::ReceiptMismatch)?,
                        conversation_events,
                        taskrun_events,
                        receipt: terminal,
                    },
                ),
            TextGenerationPhase::Rejected if unknown_terminal_cancellation.is_some() => self
                .repository
                .reject_text_generation_after_unknown_terminal_cancellation(
                    crate::ports::RejectTextGenerationAfterUnknownTerminalCancellationCommit {
                        command_id: context.command_id,
                        idempotency_key: context.idempotency_key.clone(),
                        idempotency_scope: scope,
                        command_fingerprint: fingerprint,
                        expected_conversation_version: input.started.conversation_version,
                        expected_started_taskrun_version: input.started.taskrun_version,
                        evidence: unknown_terminal_cancellation.expect("matched above"),
                        conversation_events,
                        taskrun_events,
                        receipt: terminal,
                    },
                ),
            TextGenerationPhase::Rejected if remote_artifact_cancellation.is_some() => self
                .repository
                .reject_text_generation_after_remote_artifact_cancellation(
                    crate::ports::RejectTextGenerationAfterRemoteArtifactCancellationCommit {
                        command_id: context.command_id,
                        idempotency_key: context.idempotency_key.clone(),
                        idempotency_scope: scope,
                        command_fingerprint: fingerprint,
                        expected_conversation_version: input.started.conversation_version,
                        expected_started_taskrun_version: input.started.taskrun_version,
                        evidence: remote_artifact_cancellation
                            .ok_or(ConversationTextServiceError::ReceiptMismatch)?,
                        conversation_events,
                        taskrun_events,
                        receipt: terminal,
                    },
                ),
            TextGenerationPhase::Rejected if pre_effect_cancellation.is_some() => self
                .repository
                .reject_text_generation_after_pre_effect_cancellation(
                    RejectTextGenerationAfterPreEffectCancellationCommit {
                        command_id: context.command_id,
                        idempotency_key: context.idempotency_key.clone(),
                        idempotency_scope: scope,
                        command_fingerprint: fingerprint,
                        expected_conversation_version: input.started.conversation_version,
                        expected_started_taskrun_version: input.started.taskrun_version,
                        evidence: pre_effect_cancellation.expect("matched above"),
                        conversation_events,
                        taskrun_events,
                        receipt: terminal,
                    },
                ),
            TextGenerationPhase::Rejected if no_admission_cancellation.is_some() => self
                .repository
                .reject_text_generation_after_no_admission_cancellation(
                    RejectTextGenerationAfterNoAdmissionCancellationCommit {
                        command_id: context.command_id,
                        idempotency_key: context.idempotency_key.clone(),
                        idempotency_scope: scope,
                        command_fingerprint: fingerprint,
                        expected_conversation_version: input.started.conversation_version,
                        expected_started_taskrun_version: input.started.taskrun_version,
                        evidence: no_admission_cancellation
                            .ok_or(ConversationTextServiceError::ReceiptMismatch)?,
                        conversation_events,
                        taskrun_events,
                        receipt: terminal,
                    },
                ),
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
        if remote_artifact_cancellation.is_some() {
            let receipt = match result {
                TextGenerationCommitResult::Committed { result } => result,
                TextGenerationCommitResult::Duplicate { stored_result } => stored_result,
            };
            if receipt.phase != TextGenerationPhase::Rejected
                || receipt.conversation_id != input.original.conversation_id
            {
                return Err(ConversationTextServiceError::ReceiptMismatch);
            }
            Ok(receipt)
        } else if terminal_cancellation.is_some()
            || unknown_terminal_cancellation.is_some()
            || pre_effect_cancellation.is_some()
            || no_admission_cancellation.is_some()
        {
            commit_terminal_cancellation_result(result, input.original.conversation_id)
        } else {
            commit_result(result, input.original.conversation_id)
        }
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
