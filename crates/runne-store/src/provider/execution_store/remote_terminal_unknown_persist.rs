fn persist_unknown_terminal(
    connection: &Connection,
    attempt: &ExecutionAttempt,
    selector: &ProviderTerminalUnknownSelector,
    rows: &UnknownSourceRows,
    authorization: &ProviderUnknownTerminalAuthorization,
) -> Result<(), ProviderExecutionError> {
    let disposition = unknown_disposition_code(authorization.disposition())?;
    let output = authorization.encrypted_output();
    let output_key = if let Some(payload) = output {
        let journal = load_encrypted_event(
            connection,
            selector.attempt_id(),
            selector.terminal_sequence(),
        )?
        .ok_or(ProviderExecutionError::JournalCorrupt)?;
        if !journal.terminal {
            return Err(ProviderExecutionError::JournalCorrupt);
        }
        insert_nonce(
            connection,
            journal.key,
            payload.nonce(),
            2,
            selector.attempt_id(),
            None,
        )?;
        Some(journal.key)
    } else {
        None
    };
    let publish = disposition == 1
        && rows.original.publication_allowed
        && rows.current.output_publication_allowed;
    let outbox_id = authorization.published_outbox_id().copied();
    let application_key = authorization
        .application_idempotency_key()
        .map(str::to_owned);
    if publish != outbox_id.is_some() || outbox_id.is_some() != application_key.is_some() {
        return Err(ProviderExecutionError::TerminalConflict);
    }
    let now = unix_timestamp();
    if let (Some(payload), Some(key), Some(outbox_id), Some(application_key)) =
        (output, output_key, outbox_id, application_key.as_deref())
    {
        connection.execute(
            "INSERT INTO provider_terminal_outbox(
                outbox_id,dispatch_attempt_id,terminal_sequence,call_digest_version,key_id,key_version,
                nonce,runtime_generation,profile_digest,ciphertext,plaintext_len,plaintext_digest,
                settlement_digest,application_idempotency_key,state,receipt_digest,created_at,applied_at
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,1,NULL,?15,NULL)",
            params![outbox_id.as_slice(), selector.attempt_id().as_bytes().as_slice(),
                execution_i64(selector.terminal_sequence())?, encode_call_digest_version(attempt.call_digest_version),
                key.key_id().as_slice(), execution_i64(key.key_version())?, payload.nonce().as_slice(),
                execution_i64(attempt.generation)?, attempt.profile_digest.as_slice(), payload.ciphertext(),
                execution_i64(payload.plaintext_len())?, payload.plaintext_digest().as_slice(),
                authorization.commitment().as_slice(), application_key, now],
        ).map_err(|_| ProviderExecutionError::TerminalConflict)?;
        connection.execute(
            "INSERT INTO provider_terminal_application_kinds(dispatch_attempt_id,outbox_id,application_kind) VALUES(?1,?2,1)",
            params![selector.attempt_id().as_bytes().as_slice(), outbox_id.as_slice()],
        ).map_err(|_| ProviderExecutionError::TerminalConflict)?;
    }
    let usage = authorization.usage();
    let (usage_present, input, output_tokens, cached, reasoning) =
        usage.map_or((0_i64, None, None, None, None), |value| {
            (
                1_i64,
                Some(value.input_tokens()),
                Some(value.output_tokens()),
                Some(value.cached_input_tokens()),
                Some(value.reasoning_output_tokens()),
            )
        });
    connection.execute(
        "INSERT INTO provider_unknown_terminal_receipts(
            dispatch_attempt_id,taskrun_id,taskrun_attempt_id,conversation_id,terminal_sequence,
            terminal_disposition,accounting_reason,usage_present,input_tokens,output_tokens,
            cached_input_tokens,reasoning_output_tokens,journal_digest,source_binding_digest,
            writer_owner_id,writer_lease_digest,authority_id,authority_revision,grant_digest,
            runtime_authority_id,database_generation,runtime_generation,fencing_token,profile_digest,
            pricing_revision_digest,request_digest,begin_receipt_digest,started_receipt_digest,
            claim_receipt_digest,admission_digest,taskrun_history_digest,conversation_history_digest,
            taskrun_stream_version,conversation_stream_version,call_digest_version,publication_allowed,
            principal_id,provider_id,provider_idempotency_key,admission_currency,reserve_token_id,
            reserve_token_amount,reserve_cost_id,reserve_cost_amount,output_key_id,output_key_version,
            output_nonce,output_ciphertext,output_plaintext_len,output_digest,outbox_id,
            application_idempotency_key,unknown_commitment,created_at
         ) VALUES(
            ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,
            ?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,?32,?33,?34,?35,?36,?37,?38,?39,
            ?40,?41,?42,?43,?44,?45,?46,?47,?48,?49,?50,?51,?52,?53,?54)",
        params![selector.attempt_id().as_bytes().as_slice(), rows.taskrun_id.as_bytes().as_slice(),
            rows.taskrun_attempt_id.as_bytes().as_slice(), rows.conversation_id.as_bytes().as_slice(),
            execution_i64(selector.terminal_sequence())?, disposition, unknown_reason_code(authorization.reason()),
            usage_present, input.map(execution_i64).transpose()?, output_tokens.map(execution_i64).transpose()?,
            cached.map(execution_i64).transpose()?, reasoning.map(execution_i64).transpose()?,
            authorization.journal_digest().as_slice(), authorization.source_binding_digest().as_slice(),
            rows.original.writer_owner_id, rows.original.writer_lease_digest.as_slice(), rows.authority_id.as_slice(),
            execution_i64(rows.authority_revision)?, rows.original.grant_digest.as_ref().map(|v| v.as_slice()),
            rows.runtime_authority_id.as_slice(), execution_i64(rows.database_generation)?,
            execution_i64(rows.runtime_generation)?, execution_i64(rows.fencing_token)?, rows.profile_digest.as_slice(),
            rows.pricing_revision_digest.as_slice(), rows.request_digest.as_slice(),
            rows.original.begin_receipt_digest.as_slice(), rows.original.started_receipt_digest.as_slice(),
            rows.original.claim_receipt_digest.as_ref().map(|v| v.as_slice()), rows.original.admission_digest.as_slice(),
            rows.original.taskrun_history_digest.as_slice(), rows.original.conversation_history_digest.as_slice(),
            execution_i64(rows.original.taskrun_stream_version)?, execution_i64(rows.original.conversation_stream_version)?,
            encode_call_digest_version(attempt.call_digest_version), i64::from(rows.original.publication_allowed),
            rows.principal_id, rows.provider_id, rows.provider_idempotency_key, rows.currency,
            rows.token_reservation_id.as_slice(), execution_i64(rows.token_amount)?, rows.cost_reservation_id.as_slice(),
            execution_i64(rows.cost_amount)?, output_key.map(|key| key.key_id().to_vec()),
            output_key.map(|key| execution_i64(key.key_version())).transpose()?,
            output.map(|value| value.nonce().to_vec()), output.map(|value| value.ciphertext().to_vec()),
            output.map(|value| execution_i64(value.plaintext_len())).transpose()?,
            output.map(|value| value.plaintext_digest().to_vec()), outbox_id.map(|value| value.to_vec()),
            application_key, authorization.commitment().as_slice(), now],
    ).map_err(|_| ProviderExecutionError::TerminalConflict)?;
    let next_state = if disposition == 1 { 4 } else { 5 };
    let changed = connection
        .execute(
            "UPDATE provider_dispatch_attempts SET state=?2,settlement_digest=?3
         WHERE attempt_id=?1 AND state=?4 AND fencing_token=?5 AND settlement_digest IS NULL",
            params![
                selector.attempt_id().as_bytes().as_slice(),
                next_state,
                authorization.commitment().as_slice(),
                attempt.state,
                execution_i64(selector.fencing_token())?
            ],
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if changed != 1 {
        return Err(ProviderExecutionError::StaleGeneration);
    }
    Ok(())
}

fn unknown_reason_code(
    reason: runne_runtime::provider_execution::ProviderUnknownAccountingReason,
) -> i64 {
    match reason {
        runne_runtime::provider_execution::ProviderUnknownAccountingReason::UsageUnavailable => 1,
        runne_runtime::provider_execution::ProviderUnknownAccountingReason::PricingUnavailable => 2,
        runne_runtime::provider_execution::ProviderUnknownAccountingReason::PricingInvalid => 3,
        runne_runtime::provider_execution::ProviderUnknownAccountingReason::CurrencyMismatch => 4,
    }
}

fn unknown_disposition_code(
    disposition: runne_provider::ProviderTerminalDisposition,
) -> Result<i64, ProviderExecutionError> {
    match disposition {
        runne_provider::ProviderTerminalDisposition::Completed => Ok(1),
        runne_provider::ProviderTerminalDisposition::RemoteFailed => Ok(2),
        runne_provider::ProviderTerminalDisposition::RemoteIncomplete => Ok(3),
        runne_provider::ProviderTerminalDisposition::CancelledUncertain => {
            Err(ProviderExecutionError::TerminalConflict)
        }
    }
}
