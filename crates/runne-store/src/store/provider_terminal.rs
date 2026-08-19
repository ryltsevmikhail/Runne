use runne_application::commands::BeginConversationTextInput;
use runne_application::ports::{
    CommitError, ConversationRepository, PrincipalId, StorageFailureKind, TextGenerationPhase,
    TextGenerationReceipt,
};
use runne_application::provider::ProviderTerminalOutboxRecord;
use runne_domain::conversation::ConversationEvent;
use runne_domain::id::{CommandId, IdempotencyKey};
use runne_runtime::provider_execution::{
    ProviderTerminalConversationResolveError, ProviderTerminalConversationResolver,
    RecoveredProviderConversationCommand,
};
use rusqlite::params;

use crate::codec::{StoreCodec, TextGenerationReceiptCodec};

use super::StoreTransaction;
use super::parse_helpers::storage_failure;

impl StoreTransaction {
    /// Loads one exact durable Conversation text receipt by original command identity.
    pub fn load_text_generation_receipt_by_command(
        &self,
        command_id: CommandId,
        idempotency_key: &IdempotencyKey,
    ) -> Result<TextGenerationReceipt, CommitError> {
        let bytes: Vec<u8> = self
            .inner
            .reader
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?
            .query_row(
                "SELECT command_outcome FROM command_receipts
                 WHERE command_id = ?1 AND idempotency_key = ?2",
                params![command_id.as_bytes(), idempotency_key.as_str().as_bytes()],
                |row| row.get(0),
            )
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        TextGenerationReceiptCodec
            .decode(&bytes)
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))
    }
}

impl ProviderTerminalConversationResolver for StoreTransaction {
    fn resolve_provider_terminal_conversation(
        &self,
        record: &ProviderTerminalOutboxRecord,
    ) -> Result<RecoveredProviderConversationCommand, ProviderTerminalConversationResolveError>
    {
        let stream = self
            .load_conversation(record.conversation_id)
            .map_err(|_| ProviderTerminalConversationResolveError::Unavailable)?;
        let event = stream
            .events
            .iter()
            .find(|event| {
                matches!(
                    event.payload(),
                    ConversationEvent::UserMessageAppended {
                        taskrun_id,
                        attempt_id,
                        ..
                    } if *taskrun_id == record.taskrun_id
                        && *attempt_id == record.execution_attempt_id
                )
            })
            .ok_or(ProviderTerminalConversationResolveError::Conflict)?;
        let ConversationEvent::UserMessageAppended { text, .. } = event.payload() else {
            return Err(ProviderTerminalConversationResolveError::Conflict);
        };
        let expected_version = event
            .sequence()
            .checked_sub(1)
            .ok_or(ProviderTerminalConversationResolveError::Conflict)?;
        let command_id = *event.command_id();
        let idempotency_key = event.idempotency_key().clone();
        let actor = event.actor().clone();
        let stored: Vec<u8> = self
            .inner
            .reader
            .lock()
            .map_err(|_| ProviderTerminalConversationResolveError::Unavailable)?
            .query_row(
                "SELECT command_outcome FROM command_receipts
                 WHERE command_id = ?1 AND idempotency_key = ?2",
                params![command_id.as_bytes(), idempotency_key.as_str().as_bytes()],
                |row| row.get(0),
            )
            .map_err(|_| ProviderTerminalConversationResolveError::Conflict)?;
        let started = TextGenerationReceiptCodec
            .decode(&stored)
            .map_err(|_| ProviderTerminalConversationResolveError::Conflict)?;
        if started.conversation_id != record.conversation_id
            || started.taskrun_id != record.taskrun_id
            || started.attempt_id != record.execution_attempt_id
            || !matches!(
                started.phase,
                TextGenerationPhase::Started | TextGenerationPhase::Completed
            )
        {
            return Err(ProviderTerminalConversationResolveError::Conflict);
        }
        Ok(RecoveredProviderConversationCommand {
            context: runne_application::ports::ApplicationCommandContext {
                command_id,
                idempotency_key,
                principal_id: PrincipalId(record.principal_id.clone()),
                actor,
            },
            original: BeginConversationTextInput {
                conversation_id: record.conversation_id,
                expected_version,
                text: text.clone(),
            },
            started,
        })
    }
}
