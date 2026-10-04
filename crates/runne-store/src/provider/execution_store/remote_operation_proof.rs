use runne_provider::{
    ProviderRecoveryBinding, ProviderRecoveryOperation, ProviderRemoteOperationProof,
    RemoteResponseId,
};

const RECOVERY_PROOF_TTL_SECONDS: i64 = 30;

fn reserve_remote_operation_proof(
    store: &SqliteProviderExecutionStore,
    expected: &ProviderRemoteAttemptBinding,
    response_id: &RemoteResponseId,
    operation: ProviderRecoveryOperation,
) -> Result<ProviderRemoteOperationProof, ProviderExecutionError> {
    let now = (store.now)();
    let expiry = now.checked_add(RECOVERY_PROOF_TTL_SECONDS)
        .ok_or(ProviderExecutionError::StoreUnavailable)?;
    let response_digest: [u8; 32] = Sha256::digest(response_id.as_str().as_bytes()).into();
    let mut connection = store.connection.lock().map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    expire_previous_proof(&tx, expected.dispatch_attempt_id, now)?;
    let record = read_remote_attempt_in_transaction(&tx, expected.dispatch_attempt_id)?
        .ok_or(ProviderExecutionError::TerminalConflict)?;
    let response = record.response.ok_or(ProviderExecutionError::TerminalConflict)?;
    if record.terminal.is_some() || response.binding != *expected
        || response.key.runtime_authority_id() != expected.runtime_authority_id
        || response.key.database_generation() != expected.database_generation
        || response.encrypted_response_id.plaintext_digest() != &response_digest
    {
        return Err(ProviderExecutionError::TerminalConflict);
    }
    let authority = recovery_authority(&tx, now)?;
    if operation == ProviderRecoveryOperation::RemoteCancel
        && !taskrun_provider_cancel_fence_matches(
            &tx, expected.taskrun_id, expected.taskrun_attempt_id, expected.dispatch_attempt_id,
        ).map_err(|_| ProviderExecutionError::StoreUnavailable)?
    {
        return Err(ProviderExecutionError::StaleGeneration);
    }
    ensure_current_profile_grant(&tx, expected)?;
    let mut nonce = [0_u8; 16];
    OsRng.try_fill_bytes(&mut nonce).map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if nonce == [0; 16] { return Err(ProviderExecutionError::StoreUnavailable); }
    tx.execute(
        "INSERT INTO provider_remote_operation_proofs (
          nonce,dispatch_attempt_id,taskrun_id,taskrun_attempt_id,provider_id,credential_realm,
          profile_id,profile_digest,pricing_revision_digest,request_digest,response_id_digest,
          runtime_authority_id,database_generation,runtime_generation,fencing_token,key_id,key_version,
          operation,issued_at,expires_at,state,observed_at
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,1,NULL)",
        params![nonce.as_slice(), expected.dispatch_attempt_id.as_bytes().as_slice(),
            expected.taskrun_id.as_bytes().as_slice(), expected.taskrun_attempt_id.as_bytes().as_slice(),
            expected.provider_id, expected.credential_realm, expected.profile_id,
            expected.profile_digest.as_slice(), expected.pricing_digest.as_slice(),
            expected.request_digest.as_slice(), response_digest.as_slice(),
            authority.authority.as_slice(), authority.database_generation, authority.generation,
            authority.fence, response.key.key_id().as_slice(), response.key.key_version() as i64,
            operation_code(operation), now, expiry],
    ).map_err(|_| ProviderExecutionError::StaleGeneration)?;
    tx.commit().map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let binding = ProviderRecoveryBinding::new(expected.taskrun_id, expected.taskrun_attempt_id,
        expected.dispatch_attempt_id, expected.profile_digest)
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    ProviderRemoteOperationProof::new(binding, operation, response_id, nonce, expiry as u64)
        .map_err(|_| ProviderExecutionError::JournalCorrupt)
}

struct CurrentRecoveryAuthority { authority: [u8;16], database_generation: i64, generation: i64, fence: i64 }

fn recovery_authority(tx: &Connection, now: i64) -> Result<CurrentRecoveryAuthority, ProviderExecutionError> {
    tx.query_row(
        "SELECT runtime_authority_id,database_generation,expected_generation,expected_fencing_token
         FROM provider_runtime_authority_state WHERE id=1 AND active=1
           AND expected_generation=lease_generation AND expected_fencing_token=lease_fencing_token
           AND capability_allowed=1 AND approval_allowed=1
           AND capability_expires_at>?1 AND approval_expires_at>?1",
        [now], |row| Ok(CurrentRecoveryAuthority {
            authority: row.get::<_,Vec<u8>>(0)?.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
            database_generation: row.get(1)?, generation: row.get(2)?, fence: row.get(3)?,
        }),
    ).optional().map_err(|_| ProviderExecutionError::StoreUnavailable)?
      .filter(|value| value.authority != [0;16] && value.database_generation > 0 && value.generation > 0 && value.fence > 0)
      .ok_or(ProviderExecutionError::StaleGeneration)
}

fn ensure_current_profile_grant(
    tx: &Transaction<'_>, expected: &ProviderRemoteAttemptBinding,
) -> Result<(), ProviderExecutionError> {
    let primary: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_runtime_authority_state WHERE id=1 AND active=1
          AND profile_digest=?1 AND pricing_revision_digest=?2)",
        params![expected.profile_digest.as_slice(), expected.pricing_digest.as_slice()], |row| row.get(0),
    ).map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if primary { return Ok(()); }
    let active: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_secondary_profile_grants g
          JOIN provider_secondary_profile_bindings b USING(grant_id)
          JOIN provider_runtime_authority_state s ON s.id=1
          WHERE g.runtime_authority_id=s.runtime_authority_id
            AND g.database_generation=s.database_generation AND g.enabled=1 AND b.closed_at IS NULL
            AND g.provider_id=?1 AND g.profile_id=?2 AND g.credential_realm=?3
            AND g.profile_digest=?4 AND g.pricing_revision_digest=?5
            AND b.owner_id=s.owner_id AND b.authority_revision=s.state_revision AND b.scope=s.scope
            AND b.activation_binding_kind=s.activation_binding_kind
            AND b.activation_binding_digest=s.activation_binding_digest)",
        params![expected.provider_id, expected.profile_id, expected.credential_realm,
            expected.profile_digest.as_slice(), expected.pricing_digest.as_slice()],
        |row| row.get(0),
    ).map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if active { Ok(()) } else { Err(ProviderExecutionError::StaleGeneration) }
}

fn expire_previous_proof(tx: &Transaction<'_>, attempt: DispatchAttemptId, now: i64)
    -> Result<(), ProviderExecutionError> {
    tx.execute(
        "UPDATE provider_remote_operation_proofs SET state=3,observed_at=?2
         WHERE dispatch_attempt_id=?1 AND state=1 AND expires_at<=?2",
        params![attempt.as_bytes().as_slice(), now],
    ).map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    Ok(())
}

fn operation_code(operation: ProviderRecoveryOperation) -> i64 {
    match operation { ProviderRecoveryOperation::StatusCheck => 1,
        ProviderRecoveryOperation::StreamResume => 2, ProviderRecoveryOperation::RemoteCancel => 3 }
}

pub(super) fn consume_remote_operation_observation(
    store: &SqliteProviderExecutionStore,
    proof: &ProviderRemoteOperationProof,
    status: runne_provider::ProviderRemoteResponseStatus,
) -> Result<(), ProviderExecutionError> {
    let status = match status {
        runne_provider::ProviderRemoteResponseStatus::Pending => 1,
        runne_provider::ProviderRemoteResponseStatus::Unknown => 2,
        _ => return Err(ProviderExecutionError::TerminalConflict),
    };
    let now = (store.now)();
    let mut connection = store.connection.lock().map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    consume_proof(&tx, proof, now, None, Some(status))?;
    tx.commit().map_err(|_| ProviderExecutionError::StoreUnavailable)
}

pub(super) fn validate_remote_operation_proof(
    store: &SqliteProviderExecutionStore,
    proof: &ProviderRemoteOperationProof,
    response_id: &runne_provider::RemoteResponseId,
) -> Result<(), ProviderExecutionError> {
    let now = (store.now)();
    if !proof.matches(proof.binding(), proof.operation(), response_id)
        || proof.expires_at_unix_seconds() <= now as u64
    {
        return Err(ProviderExecutionError::StaleGeneration);
    }
    let mut connection = store.connection.lock().map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let tx = connection.transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let b = proof.binding();
    let record = read_remote_attempt_in_transaction(&tx, b.provider_attempt_id())?
        .ok_or(ProviderExecutionError::TerminalConflict)?;
    let response = record.response.as_ref().ok_or(ProviderExecutionError::TerminalConflict)?;
    if record.terminal.is_some() || response.binding != record.request.binding
        || response.key != record.request.key
        || response.encrypted_response_id.plaintext_digest() != &proof.response_id_digest()
        || record.request.binding.taskrun_id != b.task_run_id()
        || record.request.binding.taskrun_attempt_id != b.task_attempt_id()
        || record.request.binding.profile_digest != b.profile_digest()
    {
        return Err(ProviderExecutionError::TerminalConflict);
    }
    ensure_current_profile_grant(&tx, &record.request.binding)?;
    let authority = recovery_authority(&tx, now)?;
    let valid: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_remote_operation_proofs p
         WHERE p.nonce=?1 AND p.dispatch_attempt_id=?2 AND p.taskrun_id=?3
           AND p.taskrun_attempt_id=?4 AND p.profile_digest=?5 AND p.response_id_digest=?6
           AND p.operation=?7 AND p.state=1 AND p.expires_at>?8
           AND p.runtime_authority_id=?9 AND p.database_generation=?10
           AND p.runtime_generation=?11 AND p.fencing_token=?12)",
        params![proof.nonce().as_slice(), b.provider_attempt_id().as_bytes().as_slice(),
            b.task_run_id().as_bytes().as_slice(), b.task_attempt_id().as_bytes().as_slice(),
            b.profile_digest().as_slice(), proof.response_id_digest().as_slice(),
            operation_code(proof.operation()), now, authority.authority.as_slice(),
            authority.database_generation, authority.generation, authority.fence],
        |row| row.get(0),
    ).map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if valid { tx.commit().map_err(|_| ProviderExecutionError::StoreUnavailable) }
    else { Err(ProviderExecutionError::StaleGeneration) }
}

fn consume_proof(
    tx: &Transaction<'_>, proof: &ProviderRemoteOperationProof, now: i64,
    artifact: Option<&ProviderRemoteTerminalRecord>,
    observed_status: Option<i64>,
) -> Result<(), ProviderExecutionError> {
    let b = proof.binding();
    let response_digest = proof.response_id_digest();
    let authority = recovery_authority(tx, now)?;
    if proof.expires_at_unix_seconds() <= now as u64 { return Err(ProviderExecutionError::StaleGeneration); }
    let changed = tx.execute(
        "UPDATE provider_remote_operation_proofs AS p SET state=2,observed_at=?1,observation_status=?13
         WHERE nonce=?2 AND dispatch_attempt_id=?3 AND taskrun_id=?4 AND taskrun_attempt_id=?5
          AND profile_digest=?6 AND response_id_digest=?7 AND operation=?8 AND state=1
          AND expires_at>?1 AND runtime_authority_id=?9 AND database_generation=?10
          AND runtime_generation=?11 AND fencing_token=?12
          AND EXISTS(SELECT 1 FROM provider_remote_request_intents q
            JOIN provider_remote_response_bindings r USING(dispatch_attempt_id)
            WHERE q.dispatch_attempt_id=p.dispatch_attempt_id AND r.dispatch_attempt_id=p.dispatch_attempt_id
              AND q.taskrun_id=p.taskrun_id AND r.taskrun_id=p.taskrun_id
              AND q.taskrun_attempt_id=p.taskrun_attempt_id AND r.taskrun_attempt_id=p.taskrun_attempt_id
              AND q.provider_id=p.provider_id AND r.provider_id=p.provider_id
              AND q.credential_realm=p.credential_realm AND r.credential_realm=p.credential_realm
              AND q.profile_id=p.profile_id AND r.profile_id=p.profile_id
              AND q.profile_digest=p.profile_digest AND r.profile_digest=p.profile_digest
              AND q.pricing_revision_digest=p.pricing_revision_digest AND r.pricing_revision_digest=p.pricing_revision_digest
              AND q.request_digest=p.request_digest AND r.request_digest=p.request_digest
              AND r.plaintext_digest=p.response_id_digest
              AND q.key_id=p.key_id AND r.key_id=p.key_id AND q.key_version=p.key_version AND r.key_version=p.key_version)",
        params![now, proof.nonce().as_slice(), b.provider_attempt_id().as_bytes().as_slice(),
            b.task_run_id().as_bytes().as_slice(), b.task_attempt_id().as_bytes().as_slice(),
            b.profile_digest().as_slice(), response_digest.as_slice(), operation_code(proof.operation()),
            authority.authority.as_slice(), authority.database_generation, authority.generation,
            authority.fence, observed_status],
    ).map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if changed != 1 { return Err(ProviderExecutionError::StaleGeneration); }
    if let Some(record) = artifact {
        if record.binding.dispatch_attempt_id != b.provider_attempt_id()
            || record.binding.taskrun_id != b.task_run_id()
            || record.binding.taskrun_attempt_id != b.task_attempt_id()
            || record.binding.profile_digest != b.profile_digest()
            || record.response_id_digest != response_digest
            || record.key != journal_key_for_artifact(tx, b.provider_attempt_id())?
        { return Err(ProviderExecutionError::TerminalConflict); }
        ensure_current_profile_grant(tx, &record.binding)?;
        let remote = read_remote_attempt_in_transaction(tx, b.provider_attempt_id())?
            .ok_or(ProviderExecutionError::TerminalConflict)?;
        if remote.terminal.is_some() || remote.response.as_ref().is_none_or(|id| id.binding != record.binding) {
            return Err(ProviderExecutionError::TerminalConflict);
        }
    } else {
        let remote = read_remote_attempt_in_transaction(tx, b.provider_attempt_id())?
            .ok_or(ProviderExecutionError::TerminalConflict)?;
        if remote.terminal.is_some() || remote.request.binding.taskrun_id != b.task_run_id()
            || remote.request.binding.taskrun_attempt_id != b.task_attempt_id()
            || remote.request.binding.profile_digest != b.profile_digest()
            || remote.response.as_ref().is_none_or(|id| id.encrypted_response_id.plaintext_digest() != &response_digest)
        { return Err(ProviderExecutionError::TerminalConflict); }
        ensure_current_profile_grant(tx, &remote.request.binding)?;
        if proof.operation() == ProviderRecoveryOperation::RemoteCancel
            && !taskrun_provider_cancel_fence_matches(tx, b.task_run_id(), b.task_attempt_id(), b.provider_attempt_id())
                .map_err(|_| ProviderExecutionError::StoreUnavailable)?
        { return Err(ProviderExecutionError::StaleGeneration); }
    }
    Ok(())
}

fn journal_key_for_artifact(tx: &Transaction<'_>, attempt: DispatchAttemptId)
    -> Result<ProviderJournalKeyBinding, ProviderExecutionError> {
    let row: (Vec<u8>, i64, Vec<u8>, i64) = tx.query_row(
        "SELECT q.key_id,q.key_version,q.runtime_authority_id,q.database_generation
         FROM provider_remote_request_intents q WHERE q.dispatch_attempt_id=?1",
        [attempt.as_bytes().as_slice()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
    ).map_err(|_| ProviderExecutionError::TerminalConflict)?;
    ProviderJournalKeyBinding::new(row.0.try_into().map_err(|_| ProviderExecutionError::JournalCorrupt)?,
        u64::try_from(row.1).map_err(|_| ProviderExecutionError::JournalCorrupt)?,
        row.2.try_into().map_err(|_| ProviderExecutionError::JournalCorrupt)?,
        u64::try_from(row.3).map_err(|_| ProviderExecutionError::JournalCorrupt)?)
        .map_err(|_| ProviderExecutionError::JournalCorrupt)
}
