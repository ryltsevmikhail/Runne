
impl<R, I, E, P> ConversationCommandHostPort for RuntimeCanonicalConversationHost<R, I, E, P>
where
    R: ConversationRepository + Send + Sync + 'static,
    I: IdGenerator + Send + Sync + 'static,
    E: ConversationRepository + Clone + Send + Sync + 'static,
    P: LocalTextProvider + 'static,
{
    async fn create_conversation(
        &self,
        context: ConversationCommandContext,
        command: CreateCanonicalConversationCommand,
    ) -> Result<ConversationCreatedAck, ConversationHostError> {
        let application_context = into_application_context(context)?;
        let input = CreateConversationInput {
            conversation_id: command.conversation_id,
            workspace_id: command.workspace_id,
            command_id: application_context.command_id,
            idempotency_key: application_context.idempotency_key.clone(),
        };
        let service = Arc::clone(&self.create_service);
        let output = tokio::task::spawn_blocking(move || {
            service.create_from_application(&application_context, input)
        })
        .await
        .map_err(|_| ConversationHostError::Unavailable)?
        .map_err(map_create_error)?;

        Ok(ConversationCreatedAck {
            conversation_id: output.conversation_id,
            workspace_id: output.workspace_id,
            stream_version: output.stream_version,
            committed_at: output.committed_at,
        })
    }

    async fn generate_text(
        &self,
        context: ConversationCommandContext,
        command: GenerateConversationTextCommand,
    ) -> Result<ConversationTextResult, ConversationHostError> {
        let application_context = into_application_context(context)?;
        let original = BeginConversationTextInput {
            conversation_id: command.conversation_id,
            expected_version: command.expected_version,
            text: command.text.into_domain(),
        };
        let started = self
            .handle
            .begin_conversation_text(application_context.clone(), original.clone())
            .await
            .map_err(map_runtime_error)?;
        let completed = match started.phase {
            TextGenerationPhase::Completed => started,
            TextGenerationPhase::Rejected => {
                return Err(ConversationHostError::ProviderOutputRejected);
            }
            TextGenerationPhase::ProhibitedInputRejected => {
                return Err(ConversationHostError::ProhibitedSecretMaterial);
            }
            TextGenerationPhase::Started => {
                if !matches!(
                    self.prohibited_content.inspect(
                        CanonicalContentBoundary::OutboundDelivery,
                        original.text.as_str().as_bytes(),
                    ),
                    Ok(ContentDisposition::Allowed { .. })
                ) {
                    let rejected = self
                        .handle
                        .finish_conversation_text(
                            application_context,
                            FinishConversationTextInput {
                                original,
                                started,
                                completion:
                                    ConversationTextCompletion::ProhibitedInputRejected {
                                    reason: runne_domain::conversation::GenerationFailureReason::ProviderOutputRejected,
                                },
                            },
                        )
                        .await
                        .map_err(map_runtime_error)?;
                    if rejected.phase != TextGenerationPhase::ProhibitedInputRejected {
                        return Err(ConversationHostError::InvariantViolation);
                    }
                    return Err(ConversationHostError::ProhibitedSecretMaterial);
                }
                if self.provider_execution {
                    match self
                        .handle
                        .execute_canonical_provider(CanonicalProviderExecutionJob {
                            context: application_context.clone(),
                            original: original.clone(),
                            started: started.clone(),
                        })
                        .await
                    {
                        Ok(receipt) => receipt,
                        Err(error) if provider_error_is_proven_pre_effect(error) => {
                            let rejected = self
                                .handle
                                .finish_conversation_text(
                                    application_context,
                                    FinishConversationTextInput {
                                        original,
                                        started,
                                        completion: ConversationTextCompletion::Rejected {
                                            reason: runne_domain::conversation::GenerationFailureReason::ProviderOutputRejected,
                                        },
                                    },
                                )
                                .await
                                .map_err(map_runtime_error)?;
                            if rejected.phase != TextGenerationPhase::Rejected {
                                return Err(ConversationHostError::InvariantViolation);
                            }
                            return Err(ConversationHostError::ProviderOutputRejected);
                        }
                        Err(error) => {
                            return Err(map_provider_execution_error(error));
                        }
                    }
                } else {
                    let assistant_text = self
                        .provider
                        .generate(&original.text)
                        .map_err(|_| ConversationHostError::InvariantViolation)?;
                    if !matches!(
                        self.prohibited_content.inspect(
                            CanonicalContentBoundary::CanonicalMutation,
                            assistant_text.as_str().as_bytes(),
                        ),
                        Ok(ContentDisposition::Allowed { .. })
                    ) {
                        let rejected = self
                        .handle
                        .finish_conversation_text(
                            application_context,
                            FinishConversationTextInput {
                                original,
                                started,
                                completion: ConversationTextCompletion::Rejected {
                                    reason: runne_domain::conversation::GenerationFailureReason::ProviderOutputRejected,
                                },
                            },
                        )
                        .await
                        .map_err(map_runtime_error)?;
                        if rejected.phase != TextGenerationPhase::Rejected {
                            return Err(ConversationHostError::InvariantViolation);
                        }
                        return Err(ConversationHostError::ProviderOutputRejected);
                    }
                    self.handle
                        .finish_conversation_text(
                            application_context,
                            FinishConversationTextInput {
                                original,
                                started,
                                completion: ConversationTextCompletion::AssistantText(
                                    assistant_text,
                                ),
                            },
                        )
                        .await
                        .map_err(map_runtime_error)?
                }
            }
        };
        if completed.phase != TextGenerationPhase::Completed {
            return Err(ConversationHostError::InvariantViolation);
        }

        let snapshot = self.list_messages(completed.conversation_id).await?;
        result_from_snapshot(completed, snapshot)
    }
}

const fn map_provider_execution_error(
    error: CanonicalProviderExecutionError,
) -> ConversationHostError {
    match error {
        CanonicalProviderExecutionError::Unavailable => ConversationHostError::Unavailable,
        CanonicalProviderExecutionError::Conflict => ConversationHostError::Conflict,
        CanonicalProviderExecutionError::RejectedBeforeEffect
        | CanonicalProviderExecutionError::RemoteFailed
        | CanonicalProviderExecutionError::RemoteIncomplete
        | CanonicalProviderExecutionError::Uncertain
        | CanonicalProviderExecutionError::PolicyDenied => {
            ConversationHostError::ProviderOutputRejected
        }
    }
}

const fn provider_error_is_proven_pre_effect(error: CanonicalProviderExecutionError) -> bool {
    matches!(error, CanonicalProviderExecutionError::RejectedBeforeEffect)
}

impl<R, I, E, P> ConversationQueryHostPort for RuntimeCanonicalConversationHost<R, I, E, P>
where
    E: ConversationRepository + Clone + Send + Sync + 'static,
    R: Send + Sync,
    I: Send + Sync,
    P: Send + Sync,
{
    async fn list_messages(
        &self,
        conversation_id: runne_domain::id::ConversationId,
    ) -> Result<ConversationMessagesSnapshot, ConversationHostError> {
        let event_store = self.event_store.clone();
        tokio::task::spawn_blocking(move || {
            let stream = event_store
                .load_conversation(conversation_id)
                .map_err(map_event_store_error)?;
            validate_loaded_stream(&stream)?;
            Conversation::replay(&stream.events).map_err(|_| ConversationHostError::Unavailable)?;

            let messages = stream
                .events
                .iter()
                .filter_map(event_to_message)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(ConversationMessagesSnapshot {
                conversation_id,
                stream_version: stream.current_version,
                messages,
            })
        })
        .await
        .map_err(|_| ConversationHostError::Unavailable)?
    }
}
