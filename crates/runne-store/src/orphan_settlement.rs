//! X2 restart settlement input: scans durable text-generation command
//! receipts left in the `Started` phase by a dead runtime instance.
//!
//! A `Started` receipt is orphaned when no worker can ever complete it: the
//! generating process died. It is *provably effect-free* — and therefore safe
//! to settle as interrupted — exactly when the linked provider execution has
//! no durable dispatch attempt: an attempt row is the record that a provider
//! request was (or is being) sent; without one, no external effect can exist
//! and the generation is terminally interrupted rather than uncertain.

use runne_application::commands::BeginConversationTextInput;
use runne_application::ports::TextGenerationReceipt;
use runne_domain::id::{CommandId, IdempotencyKey};

use crate::codec::{
    ConversationEventCodec, IdempotencyScopeCodec, StoreCodec, TextGenerationReceiptCodec,
};

/// One orphaned `Started` generation with everything the terminal finish path
/// needs to replay the original command identity exactly.
pub struct OrphanedTextGeneration {
    pub command_id: CommandId,
    pub idempotency_key: IdempotencyKey,
    pub receipt: TextGenerationReceipt,
    pub original: BeginConversationTextInput,
}

/// Scans `command_receipts` for `Started` text generations whose provider
/// execution never reached a dispatch attempt.
///
/// # Errors
///
/// Returns a closed failure when the durable state cannot be decoded or the
/// guard query fails; callers treat any failure as bootstrap-fatal
/// (fail-closed) rather than skipping settlement.
pub fn scan_provably_effect_free_started_generations(
    connection: &rusqlite::Connection,
) -> Result<Vec<OrphanedTextGeneration>, OrphanSettlementError> {
    let mut statement = connection
        .prepare(
            "SELECT command_id, idempotency_key, idempotency_scope_bytes, command_outcome
             FROM command_receipts",
        )
        .map_err(|_| OrphanSettlementError::Unavailable)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
            ))
        })
        .map_err(|_| OrphanSettlementError::Unavailable)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| OrphanSettlementError::Unavailable)?;
    drop(statement);

    let mut orphans = Vec::new();
    for (command_id_bytes, key_bytes, scope_bytes, outcome_bytes) in rows {
        // Only generate-text receipts carry a TextGenerationReceipt outcome;
        // every other operation is not this settlement's concern.
        if IdempotencyScopeCodec
            .decode(&scope_bytes)
            .map_err(|_| OrphanSettlementError::InvariantViolation)?
            .operation
            != runne_application::ports::OperationTag::GenerateConversationText
        {
            continue;
        }
        let command_id_bytes: [u8; 16] = command_id_bytes
            .as_slice()
            .try_into()
            .map_err(|_| OrphanSettlementError::InvariantViolation)?;
        let command_id = CommandId::from_bytes(command_id_bytes);
        let idempotency_key = IdempotencyKey::new(
            String::from_utf8(key_bytes).map_err(|_| OrphanSettlementError::InvariantViolation)?,
        )
        .map_err(|_| OrphanSettlementError::InvariantViolation)?;
        let receipt = TextGenerationReceiptCodec
            .decode(&outcome_bytes)
            .map_err(|_| OrphanSettlementError::InvariantViolation)?;
        if receipt.phase != runne_application::ports::TextGenerationPhase::Started {
            continue;
        }
        if provider_dispatch_attempt_exists(connection, receipt.taskrun_id)? {
            // A provider request was durably admitted: the outcome may be
            // uncertain, never settled blindly here.
            continue;
        }
        let original = begin_input_from_user_event(connection, &receipt)?;
        orphans.push(OrphanedTextGeneration {
            command_id,
            idempotency_key,
            receipt,
            original,
        });
    }
    Ok(orphans)
}

/// True when the linked provider execution recorded a dispatch attempt for
/// this coordinating task run.
fn provider_dispatch_attempt_exists(
    connection: &rusqlite::Connection,
    taskrun_id: runne_domain::id::TaskRunId,
) -> Result<bool, OrphanSettlementError> {
    connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM provider_execution_admissions admission
                JOIN provider_dispatch_attempts attempt
                  ON attempt.attempt_id = admission.dispatch_attempt_id
                WHERE admission.taskrun_id = ?1)",
            [taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .map_err(|_| OrphanSettlementError::Unavailable)
}

/// Rebuilds the original begin input by decoding the durable user message
/// the `Started` commit appended at `receipt.conversation_version`.
fn begin_input_from_user_event(
    connection: &rusqlite::Connection,
    receipt: &TextGenerationReceipt,
) -> Result<BeginConversationTextInput, OrphanSettlementError> {
    use rusqlite::OptionalExtension as _;

    let payload: Option<Vec<u8>> = connection
        .query_row(
            "SELECT payload FROM events
             WHERE aggregate_type = 2 AND aggregate_id = ?1 AND sequence = ?2",
            rusqlite::params![
                receipt.conversation_id.as_bytes(),
                receipt.conversation_version as i64
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| OrphanSettlementError::Unavailable)?;
    let payload = payload.ok_or(OrphanSettlementError::InvariantViolation)?;
    match ConversationEventCodec
        .decode(&payload)
        .map_err(|_| OrphanSettlementError::InvariantViolation)?
    {
        runne_domain::conversation::ConversationEvent::UserMessageAppended { text, .. } => {
            let expected_version = receipt
                .conversation_version
                .checked_sub(1)
                .ok_or(OrphanSettlementError::InvariantViolation)?;
            Ok(BeginConversationTextInput {
                conversation_id: receipt.conversation_id,
                expected_version,
                text,
            })
        }
        _ => Err(OrphanSettlementError::InvariantViolation),
    }
}

/// Decodes the stored idempotency scope bytes for a command, recovering the
/// original principal for exact replay of the command identity.
///
/// # Errors
///
/// Returns a closed failure when the scope row is missing or undecodable.
pub fn decode_command_scope(
    connection: &rusqlite::Connection,
    command_id: CommandId,
) -> Result<runne_application::ports::IdempotencyScope, OrphanSettlementError> {
    use rusqlite::OptionalExtension as _;

    let scope_bytes: Option<Vec<u8>> = connection
        .query_row(
            "SELECT idempotency_scope_bytes FROM command_receipts WHERE command_id = ?1",
            [command_id.as_bytes()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| OrphanSettlementError::Unavailable)?;
    let scope_bytes = scope_bytes.ok_or(OrphanSettlementError::InvariantViolation)?;
    IdempotencyScopeCodec
        .decode(&scope_bytes)
        .map_err(|_| OrphanSettlementError::InvariantViolation)
}

/// Closed scanner failure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrphanSettlementError {
    /// The durable store could not be read.
    Unavailable,
    /// Stored state violated the settlement invariants.
    InvariantViolation,
}
