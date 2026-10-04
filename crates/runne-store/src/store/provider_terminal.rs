use super::StoreTransaction;
use super::parse_helpers::storage_failure;
use crate::codec::{StoreCodec, TextGenerationReceiptCodec};
use runne_application::ports::{
    CommitError, PrincipalId, StorageFailureKind, TextGenerationReceipt,
};
use runne_domain::id::{CommandId, IdempotencyKey};
use rusqlite::params;

#[derive(Debug, Clone)]
pub struct StartedTextGenerationCommand {
    pub receipt: TextGenerationReceipt,
    pub command_id: CommandId,
    pub idempotency_key: IdempotencyKey,
    pub principal_id: PrincipalId,
}

impl StoreTransaction {
    /// Finds the unique still-Started text command bound to one TaskRun.
    pub fn find_started_text_generation_for_taskrun(
        &self,
        taskrun_id: runne_domain::id::TaskRunId,
    ) -> Result<Option<StartedTextGenerationCommand>, CommitError> {
        let connection = self
            .inner
            .reader
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
        let mut statement = connection
            .prepare(
                "SELECT command_id,idempotency_key,idempotency_scope_bytes,command_outcome
                 FROM command_receipts ORDER BY command_id",
            )
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        let rows = rows
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        let mut found = None;
        for (command, key, encoded_scope, outcome) in rows {
            let scope = crate::codec::IdempotencyScopeCodec
                .decode(&encoded_scope)
                .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
            if scope.operation != runne_application::ports::OperationTag::GenerateConversationText {
                continue;
            }
            let receipt = TextGenerationReceiptCodec
                .decode(&outcome)
                .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
            if receipt.taskrun_id != taskrun_id
                || receipt.phase != runne_application::ports::TextGenerationPhase::Started
            {
                continue;
            }
            let key = String::from_utf8(key)
                .ok()
                .and_then(|value| IdempotencyKey::new(value).ok())
                .ok_or_else(|| storage_failure(StorageFailureKind::CorruptData))?;
            let command_id = CommandId::from_bytes(
                command
                    .as_slice()
                    .try_into()
                    .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?,
            );
            let candidate = StartedTextGenerationCommand {
                receipt,
                command_id,
                idempotency_key: key,
                principal_id: scope.principal_id,
            };
            if found.replace(candidate).is_some() {
                return Err(storage_failure(StorageFailureKind::IntegrityViolation));
            }
        }
        Ok(found)
    }

    /// Reads the principal pinned by a durable text-generation command receipt.
    pub fn load_text_generation_principal_by_command(
        &self,
        command_id: CommandId,
        idempotency_key: &IdempotencyKey,
    ) -> Result<PrincipalId, CommitError> {
        let scope: Vec<u8> = self
            .inner
            .reader
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?
            .query_row(
                "SELECT idempotency_scope_bytes FROM command_receipts
                 WHERE command_id=?1 AND idempotency_key=?2",
                params![command_id.as_bytes(), idempotency_key.as_str().as_bytes()],
                |row| row.get(0),
            )
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        let scope = crate::codec::IdempotencyScopeCodec
            .decode(&scope)
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        Ok(scope.principal_id)
    }

    /// Cheap advisory check; the atomic cancellation writer independently rechecks all rows.
    pub fn has_provider_execution_admission_for_attempt(
        &self,
        taskrun_id: runne_domain::id::TaskRunId,
        attempt_id: runne_domain::id::AttemptId,
    ) -> Result<bool, CommitError> {
        let present: bool = self
            .inner
            .reader
            .lock()
            .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM provider_execution_admissions
                 WHERE taskrun_id=?1 AND execution_attempt_id=?2)",
                params![taskrun_id.as_bytes(), attempt_id.as_bytes()],
                |row| row.get(0),
            )
            .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
        Ok(present)
    }

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
