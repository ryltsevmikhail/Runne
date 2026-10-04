use super::super::event_context::valid_event_context;
use super::super::parse_helpers::storage_failure;
use super::super::*;
use runne_application::ports::RuntimeAuthorityId;
use runne_application::ports::TaskRunAssignmentIdentity;

pub(super) fn validate_claimed_text_payload(
    payload: &BeginClaimedTextGenerationCommit,
    authority: &RuntimeAuthorityId,
) -> Result<(), CommitError> {
    let receipt = &payload.receipt;
    let valid = payload.idempotency_scope.runtime_authority_id == *authority
        && payload.conversation_events.len() == 1
        && receipt.phase == TextGenerationPhase::Started
        && receipt.conversation_version
            == payload
                .expected_conversation_version
                .checked_add(1)
                .unwrap_or(0)
        && receipt.taskrun_version == payload.expected_taskrun_version
        && payload.assignment.taskrun_id == receipt.taskrun_id
        && payload.assignment.attempt_id == receipt.attempt_id
        && matches!(&payload.idempotency_scope,
            IdempotencyScope {
                operation: OperationTag::GenerateConversationText,
                aggregate_scope: AggregateScope::ExistingConversation { conversation_id },
                ..
            } if *conversation_id == receipt.conversation_id)
        && matches!(payload.conversation_events[0].payload(),
            ConversationEvent::UserMessageAppended { message_id, taskrun_id, attempt_id, text }
            if *message_id == receipt.user_message_id
                && *taskrun_id == receipt.taskrun_id
                && *attempt_id == receipt.attempt_id
                && text.as_str() == payload.submitted_prompt.as_str())
        && valid_event_context(
            &payload.conversation_events[0],
            payload.command_id,
            &payload.idempotency_key,
            AggregateId::Conversation(receipt.conversation_id),
            Sensitivity::Sensitive,
        );
    if valid {
        Ok(())
    } else {
        Err(storage_failure(StorageFailureKind::IntegrityViolation))
    }
}

pub(super) fn verify_claimed_taskrun(
    tx: &rusqlite::Transaction<'_>,
    payload: &BeginClaimedTextGenerationCommit,
    authority: &RuntimeAuthorityId,
) -> Result<(), CommitError> {
    let identity = &payload.assignment;
    let node = uuid::Uuid::parse_str(&identity.node_id.0)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    if node.is_nil()
        || node.to_string() != identity.node_id.0
        || identity.node_epoch == 0
        || identity.fence.0 == 0
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    crate::store::taskrun_assignment::verify_current_claim(tx, identity)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let now = crate::store::taskrun_assignment::now_ms(tx)
        .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
    crate::store::taskrun_assignment::ensure_live_local_node(tx, identity, *node.as_bytes(), now)
        .map_err(|_| storage_failure(StorageFailureKind::Unavailable))?;
    let occupation: Option<(i64, String, String)> = tx.query_row(
        "SELECT lease_expires_at_ms,state,dispatch_intent FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2 AND attempt_id=?3 AND node_id=?4 AND node_epoch=?5",
        params![identity.taskrun_id.as_bytes(), identity.fence.0 as i64, identity.attempt_id.as_bytes(), node.as_bytes(), identity.node_epoch as i64],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).optional().map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if !matches!(occupation, Some((expiry, ref state, ref intent)) if expiry > now && state == "active" && intent == "absent")
    {
        return Err(storage_failure(StorageFailureKind::Unavailable));
    }
    let prior_effect: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM taskrun_dispatch_intents WHERE taskrun_id=?1 AND fence=?2) OR EXISTS(SELECT 1 FROM taskrun_provider_bindings WHERE taskrun_id=?1 AND fence=?2) OR EXISTS(SELECT 1 FROM taskrun_local_command_attempts WHERE taskrun_id=?1)",
        params![identity.taskrun_id.as_bytes(), identity.fence.0 as i64], |row| row.get(0),
    ).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if prior_effect {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    let head: i64 = tx.query_row(
        "SELECT current_version FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=?1",
        [identity.taskrun_id.as_bytes()], |row| row.get(0),
    ).map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if u64::try_from(head).ok() != Some(payload.expected_taskrun_version) {
        return Err(CommitError::VersionConflict {
            expected: payload.expected_taskrun_version,
            actual: u64::try_from(head).unwrap_or(0),
        });
    }
    verify_submitter_and_prompt(tx, payload, authority)
}

pub(super) fn verify_immutable_claim_identity(
    tx: &rusqlite::Connection,
    identity: &TaskRunAssignmentIdentity,
    version: u64,
) -> Result<(), CommitError> {
    let node = uuid::Uuid::parse_str(&identity.node_id.0)
        .map_err(|_| storage_failure(StorageFailureKind::IntegrityViolation))?;
    let stored: Option<(Vec<u8>, Vec<u8>, i64, i64)> = tx.query_row(
        "SELECT attempt_id,node_id,node_epoch,new_version FROM taskrun_claim_receipts WHERE taskrun_id=?1 AND fence=?2",
        params![identity.taskrun_id.as_bytes(), identity.fence.0 as i64],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    ).optional().map_err(|_| storage_failure(StorageFailureKind::CorruptData))?;
    if matches!(stored, Some((attempt, node_id, epoch, new_version))
        if attempt.as_slice() == identity.attempt_id.as_bytes()
            && node_id == node.as_bytes()
            && epoch == identity.node_epoch as i64
            && u64::try_from(new_version).ok() == Some(version))
    {
        Ok(())
    } else {
        Err(storage_failure(StorageFailureKind::IntegrityViolation))
    }
}

fn verify_submitter_and_prompt(
    tx: &rusqlite::Transaction<'_>,
    payload: &BeginClaimedTextGenerationCommit,
    authority: &RuntimeAuthorityId,
) -> Result<(), CommitError> {
    let origin = super::super::taskrun_submit_origin::verify_submitted_v2_origin(
        tx,
        payload.receipt.taskrun_id,
        authority,
    )?
    .ok_or_else(|| storage_failure(StorageFailureKind::IntegrityViolation))?;
    if origin.conversation_id != payload.receipt.conversation_id
        || origin.workspace_id != payload.receipt.workspace_id
        || origin.input.prompt() != payload.submitted_prompt.as_str()
        || origin.principal_id != payload.idempotency_scope.principal_id
        || payload.conversation_events[0].actor() != &origin.actor
    {
        return Err(storage_failure(StorageFailureKind::IntegrityViolation));
    }
    Ok(())
}
