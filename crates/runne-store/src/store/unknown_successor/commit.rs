use super::super::*;
mod events;
mod receipts;
use super::validate::{self};
use runne_application::commands::{
    CommandOutcome, SupersedeUnknownTaskRunInput, UnknownSuccessorAcknowledgmentV1,
};
use runne_application::fingerprint::CommandFingerprint;
type UnknownSuccessorCommandReceiptRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
use runne_application::ports::{
    CommitError, StorageFailureKind, UnknownSuccessorCommit, UnknownSuccessorCommitResult,
};
use runne_application::provider::HistoricalProviderModelResolver;
use rusqlite::{OptionalExtension, Transaction, params};

pub(super) fn commit(
    store: &StoreTransaction,
    tx: Transaction<'_>,
    payload: UnknownSuccessorCommit,
    resolver: &dyn HistoricalProviderModelResolver,
) -> Result<UnknownSuccessorCommitResult, CommitError> {
    if payload.idempotency_scope.runtime_authority_id != store.runtime_authority_id {
        return Err(fail(StorageFailureKind::PolicyDenied));
    }
    let command = SupersedeUnknownTaskRunInput {
        predecessor_taskrun_id: payload.predecessor_taskrun_id,
        expected_predecessor_version: payload.expected_predecessor_version,
        acknowledgment: UnknownSuccessorAcknowledgmentV1::DuplicateExecutionAndCostV1,
    };
    if payload.acknowledgement_digest
        != UnknownSuccessorAcknowledgmentV1::DuplicateExecutionAndCostV1.digest()
        || payload.command_fingerprint
            != CommandFingerprint::for_supersede_unknown_task_run(&command)
    {
        return Err(fail(StorageFailureKind::IntegrityViolation));
    }
    let scope_codec = IdempotencyScopeCodec;
    let scope_bytes = scope_codec
        .encode(&payload.idempotency_scope)
        .map_err(|_| fail(StorageFailureKind::IntegrityViolation))?;
    guard_project_workspace_command_id(&tx, &payload)?;
    if let Some(duplicate) = duplicate_receipt(&tx, &payload, &scope_bytes)? {
        tx.commit()
            .map_err(|_| fail(StorageFailureKind::Unavailable))?;
        return Ok(duplicate);
    }
    guard_idempotency_key(&tx, &payload, &scope_bytes)?;
    let bound = validate::validate(&tx, &payload, resolver)?;
    let result = events::write_events(store, &tx, &payload, &bound)?;
    receipts::write_command_receipt(&tx, &payload, &scope_bytes, result, bound.conversation_id)?;
    receipts::write_successor_receipt(&tx, &payload, &bound, result)?;
    tx.commit()
        .map_err(|_| fail(StorageFailureKind::Unavailable))?;
    Ok(result)
}

fn guard_project_workspace_command_id(
    tx: &Transaction<'_>,
    payload: &UnknownSuccessorCommit,
) -> Result<(), CommitError> {
    let stored: Option<Vec<u8>> = tx
        .query_row(
            "SELECT semantic_fingerprint FROM project_workspace_command_receipts
             WHERE command_id=?1",
            [payload.command_id.as_bytes()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| fail(StorageFailureKind::CorruptData))?;
    if let Some(bytes) = stored {
        let fingerprint = bytes
            .try_into()
            .map_err(|_| fail(StorageFailureKind::CorruptData))?;
        return Err(CommitError::IdempotencyConflict {
            stored_command_id: payload.command_id,
            attempted_command_id: payload.command_id,
            stored_fingerprint: CommandFingerprint::from_bytes(fingerprint),
            attempted_fingerprint: payload.command_fingerprint,
        });
    }
    Ok(())
}

fn duplicate_receipt(
    tx: &Transaction<'_>,
    payload: &UnknownSuccessorCommit,
    scope: &[u8],
) -> Result<Option<UnknownSuccessorCommitResult>, CommitError> {
    let existing: Option<UnknownSuccessorCommandReceiptRow> = tx
        .query_row(
            "SELECT idempotency_scope_bytes,idempotency_key,fingerprint,command_outcome
             FROM command_receipts WHERE command_id=?1",
            [payload.command_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|_| fail(StorageFailureKind::CorruptData))?;
    let Some((stored_scope, key, fingerprint, outcome)) = existing else {
        return Ok(None);
    };
    if stored_scope != scope
        || key.as_slice() != payload.idempotency_key.as_str().as_bytes()
        || fingerprint.as_slice() != payload.command_fingerprint.as_bytes()
    {
        return Err(CommitError::IdempotencyConflict {
            stored_command_id: payload.command_id,
            attempted_command_id: payload.command_id,
            stored_fingerprint: fingerprint_from_bytes(fingerprint)?,
            attempted_fingerprint: payload.command_fingerprint,
        });
    }
    let decoded = CommandOutcomeCodec
        .decode(&outcome)
        .map_err(|_| fail(StorageFailureKind::CorruptData))?;
    match decoded {
        CommandOutcome::UnknownSuccessorCreated {
            predecessor_taskrun_id,
            predecessor_version,
            conversation_id,
            conversation_version,
            successor_taskrun_id,
            successor_version,
        } if predecessor_taskrun_id == payload.predecessor_taskrun_id => {
            let receipt: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM taskrun_unknown_successor_receipts
                     WHERE predecessor_taskrun_id=?1 AND successor_taskrun_id=?2
                       AND command_id=?3 AND command_fingerprint=?4
                       AND acknowledgement_digest=?5)",
                    params![
                        predecessor_taskrun_id.as_bytes(),
                        successor_taskrun_id.as_bytes(),
                        payload.command_id.as_bytes(),
                        payload.command_fingerprint.as_bytes().as_slice(),
                        payload.acknowledgement_digest.as_bytes().as_slice(),
                    ],
                    |row| row.get(0),
                )
                .map_err(|_| fail(StorageFailureKind::CorruptData))?;
            if !receipt {
                return Err(fail(StorageFailureKind::IntegrityViolation));
            }
            Ok(Some(UnknownSuccessorCommitResult {
                predecessor_taskrun_id,
                predecessor_version,
                conversation_id,
                conversation_version,
                successor_taskrun_id,
                successor_version,
            }))
        }
        _ => Err(fail(StorageFailureKind::IntegrityViolation)),
    }
}

fn guard_idempotency_key(
    tx: &Transaction<'_>,
    payload: &UnknownSuccessorCommit,
    scope: &[u8],
) -> Result<(), CommitError> {
    let existing: Option<(Vec<u8>, Vec<u8>)> = tx
        .query_row(
            "SELECT command_id,fingerprint FROM command_receipts
             WHERE idempotency_scope_bytes=?1 AND idempotency_key=?2",
            params![scope, payload.idempotency_key.as_str().as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| fail(StorageFailureKind::CorruptData))?;
    if let Some((command, fingerprint)) = existing {
        return Err(CommitError::IdempotencyConflict {
            stored_command_id: CommandId::from_bytes(parse_id(command)?),
            attempted_command_id: payload.command_id,
            stored_fingerprint: fingerprint_from_bytes(fingerprint)?,
            attempted_fingerprint: payload.command_fingerprint,
        });
    }
    Ok(())
}

fn fingerprint_from_bytes(bytes: Vec<u8>) -> Result<CommandFingerprint, CommitError> {
    Ok(CommandFingerprint::from_bytes(
        bytes
            .try_into()
            .map_err(|_| fail(StorageFailureKind::CorruptData))?,
    ))
}

fn parse_id(bytes: Vec<u8>) -> Result<[u8; 16], CommitError> {
    bytes
        .try_into()
        .map_err(|_| fail(StorageFailureKind::CorruptData))
}

fn fail(kind: StorageFailureKind) -> CommitError {
    CommitError::StorageFailure(kind)
}
