//! Durable conversation context-scope marker.
//!
//! Every committed Conversation carries an explicit delivery-context row
//! written in the SAME transaction as `ConversationCreated`. The marker —
//! not the absence of records — is the provenance input of the NM-06
//! delivery gate: a missing row means unknown provenance and stays denied
//! for project-scoped resolution.

use super::super::parse_helpers::*;
use super::super::*;
use super::fingerprint_compat::{
    marker_agrees_with_scope, new_conversation_ids, stored_fingerprint_matches,
};

/// Durable create-command idempotency pre-checks, extracted from
/// [`StoreTransaction::commit_conversation_impl`] to keep both files within
/// the source file length budget.
pub(super) enum CreateReceiptCheck {
    /// No prior receipt: proceed with the commit.
    Proceed,
    /// The exact command was committed previously.
    Duplicate(ConversationReceipt),
    /// A different command collides with this identity.
    Conflict(CommitError),
}

/// Replays the three project-receipt/global-receipt idempotency lookups.
/// `scope` is the already-encoded idempotency-scope bytes.
pub(super) fn check_create_receipts(
    tx: &rusqlite::Transaction<'_>,
    payload: &ConversationCommit,
    scope: &[u8],
) -> Result<CreateReceiptCheck, CommitError> {
    if let Some(stored_fingerprint) = tx
        .query_row(
            "SELECT semantic_fingerprint FROM project_workspace_command_receipts
             WHERE command_id = ?1",
            params![payload.command_id.as_bytes()],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()
        .map_err(map_commit_read_error)?
    {
        return Ok(CreateReceiptCheck::Conflict(
            CommitError::IdempotencyConflict {
                stored_command_id: payload.command_id,
                attempted_command_id: payload.command_id,
                stored_fingerprint: parse_fingerprint(stored_fingerprint)?,
                attempted_fingerprint: payload.command_fingerprint,
            },
        ));
    }

    if let Some((stored_scope, stored_key, stored_fingerprint, stored_outcome)) = tx
        .query_row(
            "SELECT idempotency_scope_bytes, idempotency_key, fingerprint, command_outcome
             FROM command_receipts WHERE command_id = ?1",
            params![payload.command_id.as_bytes()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
    {
        let stored_key = parse_idempotency_key_for_commit(stored_key)?;
        let stored_fingerprint = parse_fingerprint(stored_fingerprint)?;
        if stored_scope == scope && stored_key == payload.idempotency_key {
            let (conversation_id, workspace_id) = new_conversation_ids(&payload.idempotency_scope)?;
            if stored_fingerprint_matches(
                &stored_fingerprint,
                &payload.command_fingerprint,
                conversation_id,
                workspace_id,
                payload.context_scope,
            ) && marker_agrees_with_scope(tx, conversation_id, payload.context_scope)?
            {
                let stored_result = ConversationReceiptCodec
                    .decode(&stored_outcome)
                    .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
                return Ok(CreateReceiptCheck::Duplicate(stored_result));
            }
        }
        return Ok(CreateReceiptCheck::Conflict(
            CommitError::IdempotencyConflict {
                stored_command_id: payload.command_id,
                attempted_command_id: payload.command_id,
                stored_fingerprint,
                attempted_fingerprint: payload.command_fingerprint,
            },
        ));
    }
    if let Some((stored_command, stored_fingerprint)) = tx
        .query_row(
            "SELECT command_id, fingerprint FROM command_receipts
             WHERE idempotency_scope_bytes = ?1 AND idempotency_key = ?2",
            params![scope, payload.idempotency_key.as_str().as_bytes()],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()
        .map_err(|_| storage_failure(StorageFailureKind::CorruptData))?
    {
        return Ok(CreateReceiptCheck::Conflict(
            CommitError::IdempotencyConflict {
                stored_command_id: parse_command_id_for_commit(stored_command)?,
                attempted_command_id: payload.command_id,
                stored_fingerprint: parse_fingerprint(stored_fingerprint)?,
                attempted_fingerprint: payload.command_fingerprint,
            },
        ));
    }
    Ok(CreateReceiptCheck::Proceed)
}

impl StoreTransaction {
    /// Records the delivery-context marker in the conversation-create
    /// transaction. The insert is deliberately non-idempotent: a duplicate
    /// conversation id is an integrity violation, and a scope row can never
    /// be rewritten to reclassify an existing conversation.
    pub(super) fn record_conversation_context_scope(
        &self,
        tx: &rusqlite::Transaction<'_>,
        conversation_id: ConversationId,
        context_scope: runne_domain::conversation::ConversationContextScope,
        now: i64,
    ) -> Result<(), CommitError> {
        tx.execute(
            "INSERT INTO conversation_context_scope
             (conversation_id, context_scope, recorded_at) VALUES (?1, ?2, ?3)",
            params![conversation_id.as_bytes(), context_scope.as_str(), now],
        )
        .map(|_| ())
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))
    }

    /// Reads the durable context marker. `Ok(None)` is unknown provenance,
    /// never an implicit text-only grant.
    pub fn conversation_context_scope(
        &self,
        conversation_id: ConversationId,
    ) -> Result<Option<runne_domain::conversation::ConversationContextScope>, EventStoreError> {
        let conn = self
            .inner
            .reader
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let scope: Option<String> = conn
            .query_row(
                "SELECT context_scope FROM conversation_context_scope
                 WHERE conversation_id = ?1",
                params![conversation_id.as_bytes()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| EventStoreError::CorruptData)?;
        Ok(scope
            .and_then(|scope| runne_domain::conversation::ConversationContextScope::parse(&scope)))
    }
}
