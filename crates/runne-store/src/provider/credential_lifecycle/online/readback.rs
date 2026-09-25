use runne_provider::{
    BindCredentialReadback, ClosePreparedCredentialOperation, CredentialLifecycleError,
    CredentialOperationId, CredentialOperationSnapshot, CredentialOperationState,
    FailCredentialOperation, TombstoneCredentialOperation,
};
use rusqlite::{TransactionBehavior, params};
use sha2::{Digest, Sha256};

use super::SqliteProviderCredentialLifecycleStore;
use super::rows::{load_head, map_sql, snapshot, state_sql};

pub(super) fn observe(
    store: &SqliteProviderCredentialLifecycleStore,
    input: runne_provider::ObserveNativeEffect,
) -> Result<CredentialOperationSnapshot, CredentialLifecycleError> {
    let mut connection = store.connection.lock().map_err(super::map_lock)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sql)?;
    let operation = snapshot(
        &transaction,
        input.operation_id(),
        &store.enrollment_authority,
    )?;
    if operation.state() != CredentialOperationState::Claimed {
        return Err(CredentialLifecycleError::LifecycleClosed);
    }
    let evidence = if operation.action() == runne_provider::CredentialOperationAction::Revoke {
        let head = load_head(&transaction, operation.provider())?
            .ok_or(CredentialLifecycleError::CorruptState)?;
        let lifecycle = operation
            .lifecycle_revision()
            .get()
            .checked_add(1)
            .ok_or(CredentialLifecycleError::CorruptState)?;
        let fence = operation
            .fence()
            .get()
            .checked_add(1)
            .ok_or(CredentialLifecycleError::CorruptState)?;
        if head.hard_fenced
            || u64::try_from(head.lifecycle).ok() != Some(lifecycle)
            || u64::try_from(head.fence).ok() != Some(fence)
            || head.active.is_some()
        {
            return Err(CredentialLifecycleError::Conflict);
        }
        runne_provider::CredentialTransitionEvidence::RevokeFenceCommitted(
            runne_provider::CredentialFence::new(fence)
                .map_err(|_| CredentialLifecycleError::CorruptState)?,
        )
    } else {
        runne_provider::CredentialTransitionEvidence::None
    };
    let command = store
        .enrollment_authority
        .issue_transition_command(
            operation.action(),
            CredentialOperationState::Claimed,
            CredentialOperationState::NativeEffectObserved,
            evidence,
        )
        .map_err(|_| CredentialLifecycleError::Conflict)?;
    store
        .enrollment_authority
        .validate_transition_command(&command)
        .map_err(|_| CredentialLifecycleError::Conflict)?;
    let changed = transaction.execute("UPDATE provider_credential_operations SET state='NATIVE_EFFECT_OBSERVED', native_effect_disposition='POSSIBLE_EFFECT', updated_at=?1 WHERE operation_id=?2 AND state='CLAIMED'", params![(store.now)(), input.operation_id().as_bytes().as_slice()]).map_err(map_sql)?;
    if changed != 1 {
        return Err(CredentialLifecycleError::Conflict);
    }
    let result = snapshot(
        &transaction,
        input.operation_id(),
        &store.enrollment_authority,
    )?;
    transaction.commit().map_err(map_sql)?;
    Ok(result)
}

pub(super) fn bind(
    store: &SqliteProviderCredentialLifecycleStore,
    input: BindCredentialReadback,
) -> Result<CredentialOperationSnapshot, CredentialLifecycleError> {
    let mut connection = store.connection.lock().map_err(super::map_lock)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sql)?;
    let operation = snapshot(
        &transaction,
        input.operation_id(),
        &store.enrollment_authority,
    )?;
    if operation.state() != CredentialOperationState::NativeEffectObserved {
        return Err(CredentialLifecycleError::LifecycleClosed);
    }
    let head = load_head(&transaction, operation.provider())?
        .ok_or(CredentialLifecycleError::CorruptState)?;
    if operation.action() == runne_provider::CredentialOperationAction::RetiredVersionCleanup
        && input.disposition() == runne_provider::CredentialReadbackDisposition::ExactAbsence
        && super::retired_cleanup::revoke_advanced_head(&transaction, &operation, &head)?
    {
        let command = store
            .enrollment_authority
            .issue_transition_command(
                operation.action(),
                operation.state(),
                CredentialOperationState::Failed,
                runne_provider::CredentialTransitionEvidence::ExactAbsenceReadback(
                    input.observation_digest(),
                ),
            )
            .map_err(|_| CredentialLifecycleError::Conflict)?;
        store
            .enrollment_authority
            .validate_transition_command(&command)
            .map_err(|_| CredentialLifecycleError::Conflict)?;
        let now = (store.now)();
        let changed = transaction.execute(
            "UPDATE provider_credential_operations
             SET state='FAILED', readback_observation_digest=?1,
                 terminal_disposition='FAILED_WITH_VERIFIED_ABSENCE', updated_at=?2
             WHERE operation_id=?3 AND state='NATIVE_EFFECT_OBSERVED'",
            params![
                input.observation_digest().as_bytes().as_slice(),
                now,
                input.operation_id().as_bytes().as_slice()
            ],
        ).map_err(map_sql)?;
        if changed != 1 {
            return Err(CredentialLifecycleError::Conflict);
        }
        super::retired_cleanup::create_next(&transaction, &operation, now)?;
        let result = snapshot(
            &transaction,
            input.operation_id(),
            &store.enrollment_authority,
        )?;
        transaction.commit().map_err(map_sql)?;
        return Ok(result);
    }
    let command = store
        .enrollment_authority
        .issue_transition_command(
            operation.action(),
            CredentialOperationState::NativeEffectObserved,
            CredentialOperationState::ReadbackVerified,
            input.evidence(),
        )
        .map_err(|_| CredentialLifecycleError::Conflict)?;
    store
        .enrollment_authority
        .validate_transition_command(&command)
        .map_err(|_| CredentialLifecycleError::Conflict)?;
    let changed = transaction.execute("UPDATE provider_credential_operations SET state='READBACK_VERIFIED', readback_observation_digest=?1, updated_at=?2 WHERE operation_id=?3 AND state='NATIVE_EFFECT_OBSERVED'", params![input.observation_digest().as_bytes().as_slice(), (store.now)(), input.operation_id().as_bytes().as_slice()]).map_err(map_sql)?;
    if changed != 1 {
        return Err(CredentialLifecycleError::Conflict);
    }
    let result = snapshot(
        &transaction,
        input.operation_id(),
        &store.enrollment_authority,
    )?;
    transaction.commit().map_err(map_sql)?;
    Ok(result)
}

pub(super) fn close(
    store: &SqliteProviderCredentialLifecycleStore,
    input: ClosePreparedCredentialOperation,
    target: CredentialOperationState,
) -> Result<CredentialOperationSnapshot, CredentialLifecycleError> {
    if input.terminal_state() != target {
        return Err(CredentialLifecycleError::InvalidInput);
    }
    let mut connection = store.connection.lock().map_err(super::map_lock)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sql)?;
    let operation = snapshot(
        &transaction,
        input.operation_id(),
        &store.enrollment_authority,
    )?;
    if operation.state() != CredentialOperationState::Prepared
        || operation.action() == runne_provider::CredentialOperationAction::Revoke
    {
        return Err(CredentialLifecycleError::LifecycleClosed);
    }
    let terminal = if target == CredentialOperationState::Cancelled {
        "CANCELLED"
    } else {
        "EXPIRED"
    };
    transaction.execute("UPDATE provider_credential_ticket_attempts SET state='EXPIRED' WHERE operation_id=?1 AND state='ISSUED'", [input.operation_id().as_bytes().as_slice()]).map_err(map_sql)?;
    transaction
        .execute(
            "UPDATE provider_credential_ticket_attempts
         SET state='TOMBSTONED', terminal_digest=ticket_digest
         WHERE operation_id=?1 AND state='EXPIRED'",
            [input.operation_id().as_bytes().as_slice()],
        )
        .map_err(map_sql)?;
    transaction.execute("UPDATE provider_credential_operations SET state=?1, terminal_disposition=?2, updated_at=?3 WHERE operation_id=?4 AND state='PREPARED'", params![state_sql(target), terminal, (store.now)(), input.operation_id().as_bytes().as_slice()]).map_err(map_sql)?;
    let result = snapshot(
        &transaction,
        input.operation_id(),
        &store.enrollment_authority,
    )?;
    transaction.commit().map_err(map_sql)?;
    Ok(result)
}

pub(super) fn fail(
    store: &SqliteProviderCredentialLifecycleStore,
    input: FailCredentialOperation,
) -> Result<CredentialOperationSnapshot, CredentialLifecycleError> {
    let mut connection = store.connection.lock().map_err(super::map_lock)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sql)?;
    let operation = snapshot(
        &transaction,
        input.operation_id(),
        &store.enrollment_authority,
    )?;
    if !matches!(
        operation.state(),
        CredentialOperationState::Claimed | CredentialOperationState::NativeEffectObserved
    ) {
        return Err(CredentialLifecycleError::LifecycleClosed);
    }
    let command = store
        .enrollment_authority
        .issue_transition_command(
            operation.action(),
            operation.state(),
            CredentialOperationState::Failed,
            runne_provider::CredentialTransitionEvidence::ExactAbsenceReadback(
                input.absence_digest(),
            ),
        )
        .map_err(|_| CredentialLifecycleError::Conflict)?;
    store
        .enrollment_authority
        .validate_transition_command(&command)
        .map_err(|_| CredentialLifecycleError::Conflict)?;
    transaction.execute("UPDATE provider_credential_operations SET state='FAILED', readback_observation_digest=?1, terminal_disposition='FAILED_WITH_VERIFIED_ABSENCE', updated_at=?2 WHERE operation_id=?3 AND state=?4", params![input.absence_digest().as_bytes().as_slice(), (store.now)(), input.operation_id().as_bytes().as_slice(), state_sql(operation.state())]).map_err(map_sql)?;
    let result = snapshot(
        &transaction,
        input.operation_id(),
        &store.enrollment_authority,
    )?;
    transaction.commit().map_err(map_sql)?;
    Ok(result)
}

pub(super) fn tombstone(
    store: &SqliteProviderCredentialLifecycleStore,
    input: TombstoneCredentialOperation,
) -> Result<CredentialOperationSnapshot, CredentialLifecycleError> {
    let mut connection = store.connection.lock().map_err(super::map_lock)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sql)?;
    let operation = snapshot(
        &transaction,
        input.operation_id(),
        &store.enrollment_authority,
    )?;
    if operation.state() != input.terminal_state() {
        return Err(CredentialLifecycleError::Conflict);
    }
    let digest = tombstone_digest(input.operation_id());
    transaction.execute("UPDATE provider_credential_operations SET state='TOMBSTONED', tombstone_digest=?1, updated_at=?2 WHERE operation_id=?3 AND state=?4", params![digest.as_slice(), (store.now)(), input.operation_id().as_bytes().as_slice(), state_sql(input.terminal_state())]).map_err(map_sql)?;
    let result = snapshot(
        &transaction,
        input.operation_id(),
        &store.enrollment_authority,
    )?;
    transaction.commit().map_err(map_sql)?;
    Ok(result)
}

pub(super) fn load(
    store: &SqliteProviderCredentialLifecycleStore,
    operation: CredentialOperationId,
) -> Result<CredentialOperationSnapshot, CredentialLifecycleError> {
    let connection = store.connection.lock().map_err(super::map_lock)?;
    snapshot(&connection, operation, &store.enrollment_authority)
}
fn tombstone_digest(operation: CredentialOperationId) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"GOCODE_CREDENTIAL_OPERATION_TOMBSTONE_V1\0");
    hasher.update(operation.as_bytes());
    hasher.finalize().into()
}
