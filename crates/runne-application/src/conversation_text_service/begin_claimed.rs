use crate::ports::BeginClaimedTextGenerationCommit;

impl<R, I> ConversationTextService<R, I>
where
    R: ConversationRepository + ConversationTextRepository + EventStore,
    I: IdGenerator,
{
    pub(super) fn begin_claimed(
        &self,
        context: &ApplicationCommandContext,
        input: BeginClaimedConversationTextInput,
    ) -> Result<TextGenerationReceipt, ConversationTextServiceError> {
        if input.assignment.taskrun_id != input.taskrun_id
            || input.assignment.attempt_id != input.attempt_id
        {
            return Err(ConversationTextServiceError::ReceiptMismatch);
        }
        match self.prohibited_content.inspect(
            CanonicalContentBoundary::CanonicalMutation,
            input.original.text.as_str().as_bytes(),
        ) {
            Ok(ContentDisposition::Allowed { .. }) => {}
            _ => return Err(ConversationTextServiceError::ProhibitedSecretMaterial),
        }
        let fingerprint = CommandFingerprint::for_generate_conversation_text(
            &input.original.conversation_id, input.original.expected_version, &input.original.text,
        );
        let scope = self.scope(context, input.original.conversation_id);
        match self.repository.lookup_claimed_text_generation_receipt(
            context.command_id,
            &context.idempotency_key,
            &scope,
            &fingerprint,
            &input.assignment,
            input.taskrun_version,
        ).map_err(map_commit)? {
            TextGenerationReceiptLookup::Duplicate { stored_result } => {
                if stored_result.taskrun_version == input.taskrun_version.saturating_add(2)
                    && stored_result.phase == TextGenerationPhase::Rejected
                {
                    if stored_result.conversation_id != input.original.conversation_id
                        || !self.valid_cancelled_replay(&stored_result, input.taskrun_version)?
                    {
                        return Err(ConversationTextServiceError::ReceiptMismatch);
                    }
                } else {
                    validate_receipt(&stored_result, input.original.conversation_id)?;
                }
                let terminal_after_claim = matches!(stored_result.phase,
                    TextGenerationPhase::Completed
                        | TextGenerationPhase::Rejected
                        | TextGenerationPhase::ProhibitedInputRejected)
                    && stored_result.taskrun_version == input.taskrun_version.saturating_add(1);
                let cancelled_after_claim = stored_result.phase == TextGenerationPhase::Rejected
                    && stored_result.taskrun_version == input.taskrun_version.saturating_add(2);
                let version_matches = stored_result.taskrun_version == input.taskrun_version
                    || terminal_after_claim
                    || cancelled_after_claim;
                if stored_result.taskrun_id != input.taskrun_id
                    || stored_result.attempt_id != input.attempt_id
                    || stored_result.workspace_id != input.workspace_id
                    || !version_matches
                { return Err(ConversationTextServiceError::ReceiptMismatch); }
                return Ok(stored_result);
            }
            TextGenerationReceiptLookup::Miss => {}
        }
        let conversation_stream = self.repository.load_conversation(input.original.conversation_id)
            .map_err(map_conversation_load)?;
        validate_conversation_stream(&conversation_stream)?;
        if conversation_stream.current_version != input.original.expected_version {
            return Err(ConversationTextServiceError::Conflict);
        }
        let conversation = Conversation::replay(&conversation_stream.events)
            .map_err(|_| ConversationTextServiceError::StoredDataUnavailable)?;
        if conversation.workspace_id != input.workspace_id || conversation.active_generation().is_some() {
            return Err(ConversationTextServiceError::ReceiptMismatch);
        }
        let taskrun_stream = self.repository.load_task_run(input.taskrun_id)
            .map_err(map_conversation_load)?;
        if taskrun_stream.current_version != input.taskrun_version
            || taskrun_stream.events.len() as u64 != input.taskrun_version
        {
            return Err(ConversationTextServiceError::Conflict);
        }
        let taskrun = TaskRun::replay(&taskrun_stream.events)
            .map_err(|_| ConversationTextServiceError::StoredDataUnavailable)?;
        let snapshot = taskrun.snapshot_v1();
        if snapshot.state() != runne_domain::task_run::TaskRunState::Running
            || snapshot.active_attempt() != Some(&input.attempt_id)
            || snapshot.conversation_id() != Some(input.original.conversation_id)
            || snapshot.workspace_id() != Some(input.workspace_id)
            || snapshot.input().is_none_or(|prompt| prompt.prompt() != input.original.text.as_str())
        {
            return Err(ConversationTextServiceError::ReceiptMismatch);
        }
        let user_message_id = self.id_generator.next_message_id()
            .map_err(ConversationTextServiceError::IdGeneration)?;
        let assistant_message_id = self.id_generator.next_message_id()
            .map_err(ConversationTextServiceError::IdGeneration)?;
        let drafts = conversation.decide(runne_domain::command::ConversationCommand::AppendUserMessage {
            message_id: user_message_id,
            taskrun_id: input.taskrun_id,
            attempt_id: input.attempt_id,
            text: input.original.text.clone(),
        }).map_err(ConversationTextServiceError::ConversationDomain)?;
        let event_ids = self.id_generator.next_event_ids(drafts.len())
            .map_err(ConversationTextServiceError::IdGeneration)?;
        let events = materialize_batch(drafts, &event_ids, conversation_stream.last_event_id,
            &domain_context(context))
            .map_err(|_| ConversationTextServiceError::MaterializationFailed)?;
        let receipt = TextGenerationReceipt {
            phase: TextGenerationPhase::Started,
            conversation_id: input.original.conversation_id,
            workspace_id: input.workspace_id,
            taskrun_id: input.taskrun_id,
            attempt_id: input.attempt_id,
            user_message_id,
            assistant_message_id,
            conversation_version: conversation_stream.current_version.checked_add(1)
                .ok_or(ConversationTextServiceError::StoredDataUnavailable)?,
            taskrun_version: input.taskrun_version,
        };
        let result = self.repository.begin_claimed_text_generation(BeginClaimedTextGenerationCommit {
            command_id: context.command_id,
            idempotency_key: context.idempotency_key.clone(),
            idempotency_scope: scope,
            command_fingerprint: fingerprint,
            expected_conversation_version: input.original.expected_version,
            expected_taskrun_version: input.taskrun_version,
            submitted_prompt: input.original.text,
            assignment: input.assignment,
            conversation_events: events,
            receipt,
        }).map_err(map_commit)?;
        commit_result(result, input.original.conversation_id)
    }

    fn valid_cancelled_replay(
        &self,
        receipt: &TextGenerationReceipt,
        claim_version: u64,
    ) -> Result<bool, ConversationTextServiceError> {
        let stream = self.repository.load_task_run(receipt.taskrun_id)
            .map_err(map_conversation_load)?;
        if stream.current_version != receipt.taskrun_version
            || stream.events.len() as u64 != receipt.taskrun_version
        { return Ok(false) }
        let cancelled = TaskRun::replay(&stream.events)
            .map_err(|_| ConversationTextServiceError::StoredDataUnavailable)?;
        Ok(cancelled.state() == runne_domain::task_run::TaskRunState::Cancelled
            && stream.events.get(claim_version as usize).is_some_and(|event|
                event.payload() == &runne_domain::task_run::TaskRunEvent::CancellationRequested)
            && stream.events.get(claim_version.saturating_add(1) as usize).is_some_and(|event|
                event.payload() == &runne_domain::task_run::TaskRunEvent::CancellationCompleted))
    }
}
