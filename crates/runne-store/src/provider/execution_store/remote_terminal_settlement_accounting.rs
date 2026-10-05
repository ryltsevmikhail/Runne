#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct RemoteTerminalSettlementResult {
    output_pending: bool,
}

fn settle_remote_terminal(
    transaction: &Transaction<'_>,
    request: &runne_runtime::provider_execution::ProviderRemoteTerminalSourceCommit,
    snapshot: &runne_application::provider::ProviderRemoteAttemptRecord,
    publication_allowed: bool,
) -> Result<RemoteTerminalSettlementResult, ProviderExecutionError> {
    let (Some(usage), Some(charge), Some(currency), Some(digest)) = (
        request.usage(),
        request.charge_micros(),
        request.currency(),
        request.settlement_digest(),
    ) else {
        return Ok(RemoteTerminalSettlementResult::default());
    };
    let attempt = load_execution_attempt(transaction, request.attempt_id())?;
    if !matches!(attempt.state, 3 | 6)
        || attempt.fencing_token != request.fencing_token()
        || attempt.generation != request.runtime_generation()
        || attempt.profile_digest != *request.profile_digest()
        || attempt.pricing_revision_digest != *request.pricing_revision_digest()
        || attempt.currency != currency
    {
        return Ok(RemoteTerminalSettlementResult::default());
    }
    let _ = secondary_profile_grant::verify_secondary_attempt_binding(
        transaction,
        request.attempt_id(),
        *request.profile_digest(),
        *request.pricing_revision_digest(),
        false,
    )?;
    let key = snapshot
        .terminal
        .as_ref()
        .ok_or(ProviderExecutionError::TerminalConflict)?
        .key;
    ensure_known_journal_key(transaction, key, &attempt)?;
    let reservations = load_reservations(transaction, &attempt.provider_idempotency_key)?;
    if usage.total_tokens() > reservations.token_amount || charge > reservations.cost_amount {
        return Ok(RemoteTerminalSettlementResult::default());
    }
    let existing: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM provider_accounting_settlements WHERE dispatch_attempt_id=?1)",
        [request.attempt_id().as_bytes().as_slice()],
        |row| row.get(0),
    ).map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let existing_outbox: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_terminal_outbox WHERE dispatch_attempt_id=?1)",
            [request.attempt_id().as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if existing || existing_outbox {
        return Err(ProviderExecutionError::TerminalConflict);
    }
    transaction
        .execute(
            "INSERT INTO provider_accounting_settlements (
          dispatch_attempt_id,pricing_revision_digest,input_tokens,output_tokens,
          cached_input_tokens,reasoning_output_tokens,charge_micros,currency,
          settlement_digest,committed_at)
         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,unixepoch())",
            rusqlite::params![
                request.attempt_id().as_bytes().as_slice(),
                request.pricing_revision_digest().as_slice(),
                execution_i64(usage.input_tokens())?,
                execution_i64(usage.output_tokens())?,
                execution_i64(usage.cached_input_tokens())?,
                execution_i64(usage.reasoning_output_tokens())?,
                execution_i64(charge)?,
                currency,
                digest.as_slice(),
            ],
        )
        .map_err(|_| ProviderExecutionError::TerminalConflict)?;
    let output_pending = request.terminal_status()
        == runne_application::provider::ProviderRemoteTerminalDisposition::Completed
        && request.publication_disposition()
            == runne_provider::ProviderRemotePublicationDisposition::Allowed
        && request.output_digest().is_some()
        && publication_allowed;
    let terminal_disposition = if output_pending {
        1
    } else {
        match request.terminal_status() {
            runne_application::provider::ProviderRemoteTerminalDisposition::Completed => 4,
            runne_application::provider::ProviderRemoteTerminalDisposition::Failed => 2,
            runne_application::provider::ProviderRemoteTerminalDisposition::Incomplete => 3,
            runne_application::provider::ProviderRemoteTerminalDisposition::Cancelled => 5,
        }
    };
    transaction.execute(
        "INSERT INTO provider_terminal_dispositions(dispatch_attempt_id,disposition) VALUES(?1,?2)",
        rusqlite::params![request.attempt_id().as_bytes().as_slice(), terminal_disposition],
    ).map_err(|_| ProviderExecutionError::TerminalConflict)?;
    if output_pending {
        let terminal = snapshot.terminal.as_ref().expect("checked above");
        let mut outbox_hash = Sha256::new();
        outbox_hash.update(b"GOCODE_PROVIDER_REMOTE_ARTIFACT_OUTBOX_V1\0");
        outbox_hash.update(request.attempt_id().as_bytes());
        outbox_hash.update(request.artifact_digest().as_slice());
        let outbox_digest: [u8; 32] = outbox_hash.finalize().into();
        let outbox_id: [u8; 16] = outbox_digest[..16]
            .try_into()
            .map_err(|_| ProviderExecutionError::TerminalConflict)?;
        let attempt_hex = request
            .attempt_id()
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let idempotency_key = format!("remote-artifact-{attempt_hex}");
        transaction
            .execute(
                "INSERT INTO provider_terminal_outbox(
          outbox_id,dispatch_attempt_id,terminal_sequence,call_digest_version,
          key_id,key_version,nonce,runtime_generation,profile_digest,ciphertext,
          plaintext_len,plaintext_digest,settlement_digest,application_idempotency_key,
          state,receipt_digest,created_at,applied_at)
         VALUES(?1,?2,0,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,1,NULL,unixepoch(),NULL)",
                rusqlite::params![
                    outbox_id.as_slice(),
                    request.attempt_id().as_bytes().as_slice(),
                    encode_call_digest_version(attempt.call_digest_version),
                    terminal.key.key_id().as_slice(),
                    execution_i64(terminal.key.key_version())?,
                    terminal.encrypted_artifact.nonce().as_slice(),
                    execution_i64(request.runtime_generation())?,
                    request.profile_digest().as_slice(),
                    terminal.encrypted_artifact.ciphertext(),
                    execution_i64(terminal.encrypted_artifact.plaintext_len())?,
                    terminal.encrypted_artifact.plaintext_digest().as_slice(),
                    digest.as_slice(),
                    idempotency_key,
                ],
            )
            .map_err(|_| ProviderExecutionError::TerminalConflict)?;
        transaction.execute(
            "INSERT INTO provider_terminal_application_kinds(dispatch_attempt_id,outbox_id,application_kind) VALUES(?1,?2,1)",
            rusqlite::params![request.attempt_id().as_bytes().as_slice(), outbox_id.as_slice()],
        ).map_err(|_| ProviderExecutionError::TerminalConflict)?;
    }
    release_reservations(
        transaction,
        &attempt.provider_idempotency_key,
        usage.total_tokens(),
        charge,
        reservations,
        unix_timestamp(),
    )?;
    if attempt.state == 3 {
        let changed = transaction
            .execute(
                "UPDATE provider_dispatch_attempts SET state=4,settlement_digest=?3
             WHERE attempt_id=?1 AND fencing_token=?2 AND state=3",
                rusqlite::params![
                    request.attempt_id().as_bytes().as_slice(),
                    execution_i64(request.fencing_token())?,
                    digest.as_slice(),
                ],
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if changed != 1 {
            return Err(ProviderExecutionError::StaleGeneration);
        }
    } else if attempt.state != 6 {
        return Err(ProviderExecutionError::StaleGeneration);
    }
    Ok(RemoteTerminalSettlementResult { output_pending })
}

fn promote_remote_source_settlement(
    transaction: &Transaction<'_>,
    request: &runne_runtime::provider_execution::ProviderRemoteTerminalSourceCommit,
) -> Result<(), ProviderExecutionError> {
    let (Some(charge), Some(currency), Some(digest)) = (
        request.charge_micros(),
        request.currency(),
        request.settlement_digest(),
    ) else {
        return Err(ProviderExecutionError::TerminalConflict);
    };
    let changed = transaction
        .execute(
            "UPDATE provider_remote_terminal_settlements
         SET settlement_state=2,charge_micros=?2,currency=?3,settlement_digest=?4
         WHERE dispatch_attempt_id=?1 AND settlement_state=1",
            rusqlite::params![
                request.attempt_id().as_bytes().as_slice(),
                execution_i64(charge)?,
                currency,
                digest.as_slice(),
            ],
        )
        .map_err(|_| ProviderExecutionError::TerminalConflict)?;
    if changed != 1 {
        return Err(ProviderExecutionError::TerminalConflict);
    }
    Ok(())
}

fn mark_remote_source_audit_only(
    transaction: &Transaction<'_>,
    request: &runne_runtime::provider_execution::ProviderRemoteTerminalSourceCommit,
) -> Result<(), ProviderExecutionError> {
    let changed = transaction
        .execute(
            "UPDATE provider_remote_terminal_settlements
             SET settlement_state=3
             WHERE dispatch_attempt_id=?1 AND settlement_state=1",
            [request.attempt_id().as_bytes().as_slice()],
        )
        .map_err(|_| ProviderExecutionError::TerminalConflict)?;
    if changed == 1 {
        return Ok(());
    }
    let already_audit_only: bool = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM provider_remote_terminal_settlements
                WHERE dispatch_attempt_id=?1 AND source_kind=2 AND settlement_state=3
                  AND taskrun_id=?2 AND taskrun_attempt_id=?3
                  AND request_digest=?4 AND response_id_digest=?5 AND artifact_digest=?6
                  AND terminal_status=?7 AND publication_disposition=?8
                  AND profile_digest=?9 AND pricing_revision_digest=?10
                  AND runtime_authority_id=?11 AND database_generation=?12
                  AND runtime_generation=?13 AND fencing_token=?14
                  AND published_output_digest IS ?15
            )",
            rusqlite::params![
                request.attempt_id().as_bytes().as_slice(),
                request.taskrun_id().as_bytes().as_slice(),
                request.taskrun_attempt_id().as_bytes().as_slice(),
                request.request_digest().as_slice(),
                request.response_id_digest().as_slice(),
                request.artifact_digest().as_slice(),
                request.terminal_status().code(),
                publication_code(request.publication_disposition()),
                request.profile_digest().as_slice(),
                request.pricing_revision_digest().as_slice(),
                request.runtime_authority_id().as_slice(),
                i64::try_from(request.database_generation())
                    .map_err(|_| ProviderExecutionError::TerminalConflict)?,
                i64::try_from(request.runtime_generation())
                    .map_err(|_| ProviderExecutionError::TerminalConflict)?,
                i64::try_from(request.fencing_token())
                    .map_err(|_| ProviderExecutionError::TerminalConflict)?,
                request.output_digest().map(|digest| digest.as_slice()),
            ],
            |row| row.get(0),
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if already_audit_only {
        Ok(())
    } else {
        Err(ProviderExecutionError::TerminalConflict)
    }
}
