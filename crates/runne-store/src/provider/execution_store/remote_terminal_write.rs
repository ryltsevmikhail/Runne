use runne_application::provider::{
    ProviderRemoteAttemptRecord, ProviderRemoteTerminalDisposition, ProviderRemoteTerminalRecord,
};

type SavedRemoteTerminalBinding = Option<(Vec<u8>, i64, Vec<u8>, Vec<u8>, Vec<u8>, i64)>;

fn persist_remote_terminal_artifact(
    store: &SqliteProviderExecutionStore,
    record: &ProviderRemoteTerminalRecord,
) -> Result<(), ProviderExecutionError> {
    persist_remote_terminal_artifact_inner(store, record, None)
}

pub(super) fn persist_remote_terminal_artifact_with_proof(
    store: &SqliteProviderExecutionStore,
    record: &ProviderRemoteTerminalRecord,
    proof: &runne_provider::ProviderRemoteOperationProof,
) -> Result<(), ProviderExecutionError> {
    persist_remote_terminal_artifact_inner(store, record, Some(proof))
}

fn persist_remote_terminal_artifact_inner(
    store: &SqliteProviderExecutionStore,
    record: &ProviderRemoteTerminalRecord,
    proof: Option<&runne_provider::ProviderRemoteOperationProof>,
) -> Result<(), ProviderExecutionError> {
    let binding = &record.binding;
    validate_remote_identity(binding, record.key, &record.encrypted_artifact, 131_072)?;
    let mut connection = store
        .connection
        .lock()
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let now = (store.now)();
    if let Some(proof) = proof {
        consume_proof(&tx, proof, now, Some(record), None)?;
    } else {
        validate_current_remote_artifact_binding(&tx, binding, record.key, now)?;
    }
    let saved: SavedRemoteTerminalBinding = tx.query_row(
        "SELECT q.key_id,q.key_version,q.request_digest,r.plaintext_digest,r.key_id,r.key_version
         FROM provider_remote_request_intents q
         JOIN provider_remote_response_bindings r USING(dispatch_attempt_id)
         WHERE q.dispatch_attempt_id=?1 AND r.dispatch_attempt_id=?1
           AND q.taskrun_id=?2 AND r.taskrun_id=?2
           AND q.taskrun_attempt_id=?3 AND r.taskrun_attempt_id=?3
           AND q.provider_id=?4 AND r.provider_id=?4
           AND q.profile_id=?5 AND r.profile_id=?5
           AND q.profile_digest=?6 AND r.profile_digest=?6
           AND q.pricing_revision_digest=?7 AND r.pricing_revision_digest=?7
           AND q.credential_realm=?8 AND r.credential_realm=?8
           AND q.request_digest=?9 AND r.request_digest=?9
           AND q.runtime_authority_id=?10 AND r.runtime_authority_id=?10
           AND q.database_generation=?11 AND r.database_generation=?11
           AND q.runtime_generation=?12 AND r.runtime_generation=?12
           AND q.fencing_token=?13 AND r.fencing_token=?13",
        params![binding.dispatch_attempt_id.as_bytes().as_slice(),binding.taskrun_id.as_bytes().as_slice(),
            binding.taskrun_attempt_id.as_bytes().as_slice(),binding.provider_id,binding.profile_id,
            binding.profile_digest.as_slice(),binding.pricing_digest.as_slice(),binding.credential_realm,
            binding.request_digest.as_slice(),binding.runtime_authority_id.as_slice(),
            i64::try_from(binding.database_generation).unwrap_or(-1),i64::try_from(binding.runtime_generation).unwrap_or(-1),
            i64::try_from(binding.fencing_token).unwrap_or(-1)],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
    ).optional().map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let Some((
        key_id,
        key_version,
        request_digest,
        response_digest,
        response_key_id,
        response_key_version,
    )) = saved
    else {
        return Err(ProviderExecutionError::TerminalConflict);
    };
    if key_id.as_slice() != record.key.key_id().as_slice()
        || key_version != i64::try_from(record.key.key_version()).unwrap_or(-1)
        || response_key_version != key_version
        || response_key_id != key_id
        || request_digest.as_slice() != binding.request_digest
        || response_digest.as_slice() != record.response_id_digest
    {
        return Err(ProviderExecutionError::TerminalConflict);
    }
    let existing: Option<(Vec<u8>, i64, Vec<u8>)> = tx.query_row(
        "SELECT plaintext_digest,disposition,response_id_digest FROM provider_remote_terminal_artifacts WHERE dispatch_attempt_id=?1",
        [binding.dispatch_attempt_id.as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).optional().map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if let Some((digest, disposition, response_id_digest)) = existing {
        return if digest.as_slice() == record.encrypted_artifact.plaintext_digest()
            && disposition == record.disposition.code()
            && response_id_digest.as_slice() == record.response_id_digest
        {
            Ok(())
        } else {
            Err(ProviderExecutionError::TerminalConflict)
        };
    }
    insert_nonce(
        &tx,
        record.key,
        record.encrypted_artifact.nonce(),
        2,
        binding.dispatch_attempt_id,
        None,
    )?;
    tx.execute(
        "INSERT INTO provider_remote_terminal_artifacts(
           dispatch_attempt_id,taskrun_id,taskrun_attempt_id,provider_id,profile_id,profile_digest,
           pricing_revision_digest,semantic_digest,prepared_digest,credential_realm,request_digest,response_id_digest,runtime_authority_id,
           database_generation,runtime_generation,fencing_token,key_id,key_version,nonce,ciphertext,
           plaintext_len,plaintext_digest,disposition,created_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,unixepoch())",
        params![binding.dispatch_attempt_id.as_bytes().as_slice(),binding.taskrun_id.as_bytes().as_slice(),
            binding.taskrun_attempt_id.as_bytes().as_slice(),binding.provider_id,binding.profile_id,
            binding.profile_digest.as_slice(),binding.pricing_digest.as_slice(),binding.semantic_digest.as_slice(),
            binding.prepared_digest.as_slice(),binding.credential_realm,binding.request_digest.as_slice(),
            record.response_id_digest.as_slice(),binding.runtime_authority_id.as_slice(),
            i64::try_from(binding.database_generation).unwrap_or(-1),i64::try_from(binding.runtime_generation).unwrap_or(-1),
            i64::try_from(binding.fencing_token).unwrap_or(-1),record.key.key_id().as_slice(),
            i64::try_from(record.key.key_version()).unwrap_or(-1),record.encrypted_artifact.nonce().as_slice(),
            record.encrypted_artifact.ciphertext(),record.encrypted_artifact.plaintext_len() as i64,
            record.encrypted_artifact.plaintext_digest().as_slice(),record.disposition.code()],
    ).map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    tx.commit()
        .map_err(|_| ProviderExecutionError::StoreUnavailable)
}

fn validate_current_remote_artifact_binding(
    tx: &rusqlite::Transaction<'_>,
    b: &ProviderRemoteAttemptBinding,
    key: ProviderJournalKeyBinding,
    now: i64,
) -> Result<(), ProviderExecutionError> {
    let valid: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_execution_admissions a
         JOIN provider_dispatch_attempts d ON d.attempt_id=a.dispatch_attempt_id
         JOIN provider_effect_starts e USING(dispatch_attempt_id)
         JOIN provider_online_dispatch_claim_providers p USING(dispatch_attempt_id)
         JOIN provider_online_credential_effect_bindings c USING(dispatch_attempt_id)
         JOIN provider_runtime_authority_state s ON s.id=1
         JOIN provider_journal_key_refs k ON k.key_id=?12 AND k.key_version=?13
         WHERE a.dispatch_attempt_id=?1 AND a.taskrun_id=?2 AND a.execution_attempt_id=?3
           AND a.provider_idempotency_key IS NOT NULL
           AND a.profile_digest=?4 AND a.pricing_revision_digest=?5
           AND a.semantic_digest=?6 AND a.prepared_digest=?7 AND a.render_digest=?8
           AND a.runtime_authority_id=?9 AND a.database_generation=?10
           AND a.generation=?11 AND a.fencing_token=?15
           AND e.permit_id=a.permit_id AND e.provider_idempotency_key=a.provider_idempotency_key
           AND e.state=1 AND e.effect_started_at<=?16 AND e.effect_expires_at>?16
           AND p.provider_id=?14 AND c.provider_id=?17
           AND s.active=1 AND s.runtime_authority_id=?9 AND s.database_generation=?10
           AND s.expected_generation=?11 AND s.lease_generation=?11
           AND s.expected_fencing_token=?15 AND s.lease_fencing_token=?15
           AND k.runtime_authority_id=?9 AND k.database_generation=?10)",
            params![
                b.dispatch_attempt_id.as_bytes().as_slice(),
                b.taskrun_id.as_bytes().as_slice(),
                b.taskrun_attempt_id.as_bytes().as_slice(),
                b.profile_digest.as_slice(),
                b.pricing_digest.as_slice(),
                b.semantic_digest.as_slice(),
                b.prepared_digest.as_slice(),
                b.request_digest.as_slice(),
                b.runtime_authority_id.as_slice(),
                i64::try_from(b.database_generation).unwrap_or(-1),
                i64::try_from(b.runtime_generation).unwrap_or(-1),
                key.key_id().as_slice(),
                i64::try_from(key.key_version()).unwrap_or(-1),
                b.provider_id,
                i64::try_from(b.fencing_token).unwrap_or(-1),
                now,
                b.credential_realm
            ],
            |row| row.get(0),
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if !valid {
        return Err(ProviderExecutionError::StaleGeneration);
    }
    super::dispatch_store::verify_online_publication(tx, b.dispatch_attempt_id, Some(now))
        .map_err(|_| ProviderExecutionError::StaleGeneration)?;
    let primary: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_runtime_authority_state WHERE id=1 AND active=1 AND profile_digest=?1 AND pricing_revision_digest=?2)",
        params![b.profile_digest.as_slice(), b.pricing_digest.as_slice()], |row| row.get(0),
    ).map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if primary {
        return Ok(());
    }
    if !secondary_profile_grant::verify_secondary_attempt_binding(
        tx,
        b.dispatch_attempt_id,
        b.profile_digest,
        b.pricing_digest,
        true,
    )? {
        return Err(ProviderExecutionError::StaleGeneration);
    }
    Ok(())
}
