impl<R, I> ConversationTextService<R, I>
where
    R: ConversationRepository + ConversationTextRepository + EventStore,
    I: IdGenerator,
{
    /// Durably appends the user message and starts its exact TaskRun attempt.
    pub fn begin(
        &self,
        context: &ApplicationCommandContext,
        input: BeginConversationTextInput,
    ) -> Result<TextGenerationReceipt, ConversationTextServiceError> {
        match self.prohibited_content.inspect(
            CanonicalContentBoundary::CanonicalMutation,
            input.text.as_str().as_bytes(),
        ) {
            Ok(ContentDisposition::Allowed { .. }) => {}
            Ok(ContentDisposition::Prohibited { .. }) | Err(_) => {
                return Err(ConversationTextServiceError::ProhibitedSecretMaterial);
            }
        }
        let fingerprint = CommandFingerprint::for_generate_conversation_text(
            &input.conversation_id,
            input.expected_version,
            &input.text,
        );
        let scope = self.scope(context, input.conversation_id);
        match self
            .repository
            .lookup_text_generation_receipt(
                context.command_id,
                &context.idempotency_key,
                &scope,
                &fingerprint,
            )
            .map_err(map_commit)?
        {
            TextGenerationReceiptLookup::Miss => {}
            TextGenerationReceiptLookup::Duplicate { stored_result } => {
                validate_receipt(&stored_result, input.conversation_id)?;
                return Ok(stored_result);
            }
        }

        let stream = self
            .repository
            .load_conversation(input.conversation_id)
            .map_err(map_conversation_load)?;
        validate_conversation_stream(&stream)?;
        if stream.current_version != input.expected_version {
            return Err(ConversationTextServiceError::Conflict);
        }
        let conversation = Conversation::replay(&stream.events)
            .map_err(|_| ConversationTextServiceError::StoredDataUnavailable)?;

        let taskrun_id = self
            .id_generator
            .next_taskrun_id()
            .map_err(ConversationTextServiceError::IdGeneration)?;
        let attempt_id = self
            .id_generator
            .next_attempt_id()
            .map_err(ConversationTextServiceError::IdGeneration)?;
        let user_message_id = self
            .id_generator
            .next_message_id()
            .map_err(ConversationTextServiceError::IdGeneration)?;
        let assistant_message_id = self
            .id_generator
            .next_message_id()
            .map_err(ConversationTextServiceError::IdGeneration)?;

        let conversation_drafts = conversation
            .decide(
                runne_domain::command::ConversationCommand::AppendUserMessage {
                    message_id: user_message_id,
                    taskrun_id,
                    attempt_id,
                    text: input.text.clone(),
                },
            )
            .map_err(ConversationTextServiceError::ConversationDomain)?;
        let taskrun_drafts = TaskRun::decide_create_running(
            CreateTaskRun {
                taskrun_id,
                conversation_id: input.conversation_id,
                workspace_id: conversation.workspace_id,
            },
            attempt_id,
        )
        .map_err(|_| ConversationTextServiceError::TaskRunDomain)?;
        let event_ids = self
            .id_generator
            .next_event_ids(conversation_drafts.len() + taskrun_drafts.len())
            .map_err(ConversationTextServiceError::IdGeneration)?;
        let domain_context = domain_context(context);
        let split = conversation_drafts.len();
        let conversation_events = materialize_batch(
            conversation_drafts,
            &event_ids[..split],
            stream.last_event_id,
            &domain_context,
        )
        .map_err(|_| ConversationTextServiceError::MaterializationFailed)?;
        let taskrun_events =
            materialize_batch(taskrun_drafts, &event_ids[split..], None, &domain_context)
                .map_err(|_| ConversationTextServiceError::MaterializationFailed)?;
        let receipt = TextGenerationReceipt {
            phase: TextGenerationPhase::Started,
            conversation_id: input.conversation_id,
            workspace_id: conversation.workspace_id,
            taskrun_id,
            attempt_id,
            user_message_id,
            assistant_message_id,
            conversation_version: stream
                .current_version
                .checked_add(1)
                .ok_or(ConversationTextServiceError::StoredDataUnavailable)?,
            taskrun_version: 4,
        };

        let result = self
            .repository
            .begin_text_generation(BeginTextGenerationCommit {
                command_id: context.command_id,
                idempotency_key: context.idempotency_key.clone(),
                idempotency_scope: scope,
                command_fingerprint: fingerprint,
                expected_conversation_version: input.expected_version,
                conversation_events,
                taskrun_events,
                receipt,
            })
            .map_err(map_commit)?;
        commit_result(result, input.conversation_id)
    }
}
