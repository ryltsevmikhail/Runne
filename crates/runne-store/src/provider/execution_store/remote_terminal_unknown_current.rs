include!("remote_terminal_unknown_current_expectation.rs");

fn load_unknown_current_facts(
    connection: &Connection,
    expected: UnknownCurrentExpectation<'_>,
) -> Result<ProviderUnknownTerminalCurrentFacts, ProviderExecutionError> {
    let UnknownCurrentExpectation {
        taskrun_id,
        taskrun_attempt_id,
        conversation_id,
        attempt,
        original_principal,
        grant_digest,
        grant_active,
    } = expected;
    let taskrun =
        crate::store::taskrun_claim::stream_validate::verify_stream(connection, taskrun_id, None)
            .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    let conversation = crate::store::load_conversation_from_connection(connection, conversation_id)
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    let conversation_aggregate =
        runne_domain::conversation::Conversation::replay(&conversation.events)
            .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    let current_writer_matches: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM conversation_writer_leases
             WHERE conversation_id=?1 AND owner_principal=?2 AND fencing_token>0)",
            params![conversation_id.as_bytes().as_slice(), original_principal],
            |row| row.get(0),
        )
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    let current_generation_matches =
        conversation_aggregate
            .active_generation()
            .is_some_and(|generation| {
                generation.taskrun_id == taskrun_id && generation.attempt_id == taskrun_attempt_id
            });
    let source_state = match taskrun.state {
        runne_domain::task_run::TaskRunState::Running => ProviderUnknownSourceState::Running,
        runne_domain::task_run::TaskRunState::Cancelling => ProviderUnknownSourceState::Cancelling,
        runne_domain::task_run::TaskRunState::Cancelled => ProviderUnknownSourceState::Cancelled,
        runne_domain::task_run::TaskRunState::Succeeded => ProviderUnknownSourceState::Completed,
        runne_domain::task_run::TaskRunState::Failed
        | runne_domain::task_run::TaskRunState::BudgetExhausted
        | runne_domain::task_run::TaskRunState::PolicyDenied
        | runne_domain::task_run::TaskRunState::Unrecoverable => ProviderUnknownSourceState::Failed,
        _ => return Err(ProviderExecutionError::TerminalConflict),
    };
    let authority_revision: u64 = connection.query_row(
        "SELECT state_revision FROM provider_runtime_authority_state WHERE id=1 AND runtime_authority_id=?1",
        [attempt.runtime_authority_id.as_slice()],
        |row| positive_u64(row.get(0)?),
    ).optional().map_err(|_| ProviderExecutionError::JournalCorrupt)?
      .ok_or(ProviderExecutionError::JournalCorrupt)?;
    let receipt: Option<UnknownReceiptCurrent> = connection
        .query_row(
            "SELECT r.accounting_reason,r.terminal_disposition,r.usage_present,
                    r.input_tokens,r.output_tokens,r.cached_input_tokens,r.reasoning_output_tokens,
                    r.output_key_id,r.output_key_version,r.output_nonce,r.output_ciphertext,
                    r.output_plaintext_len,r.output_digest,r.outbox_id,r.unknown_commitment,
                    o.receipt_digest,k.runtime_authority_id,k.database_generation,
                    r.terminal_sequence,r.application_idempotency_key
             FROM provider_unknown_terminal_receipts r
             LEFT JOIN provider_terminal_outbox o ON o.outbox_id=r.outbox_id
             LEFT JOIN provider_journal_key_refs k ON k.key_id=r.output_key_id
                  AND k.key_version=r.output_key_version
             WHERE r.dispatch_attempt_id=?1",
            [attempt.dispatch_attempt_id.as_bytes().as_slice()],
            |row| {
                let output = match (
                    row.get::<_, Option<Vec<u8>>>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                    row.get::<_, Option<Vec<u8>>>(9)?,
                    row.get::<_, Option<Vec<u8>>>(10)?,
                    row.get::<_, Option<i64>>(11)?,
                    row.get::<_, Option<Vec<u8>>>(12)?,
                    row.get::<_, Option<Vec<u8>>>(16)?,
                    row.get::<_, Option<i64>>(17)?,
                ) {
                    (
                        Some(key),
                        Some(version),
                        Some(nonce),
                        Some(cipher),
                        Some(len),
                        Some(digest),
                        Some(authority),
                        Some(generation),
                    ) => Some((
                        key, version, nonce, cipher, len, digest, authority, generation,
                    )),
                    (None, None, None, None, None, None, None, None) => None,
                    _ => return Err(rusqlite::Error::InvalidQuery),
                };
                Ok(UnknownReceiptCurrent {
                    reason: row.get(0)?,
                    disposition: row.get(1)?,
                    usage_present: row.get(2)?,
                    input: row.get(3)?,
                    output_tokens: row.get(4)?,
                    cached: row.get(5)?,
                    reasoning: row.get(6)?,
                    output,
                    outbox_id: row.get(13)?,
                    commitment: row.get(14)?,
                    ack: row.get(15)?,
                    terminal_sequence: row.get(18)?,
                    application_key: row.get(19)?,
                })
            },
        )
        .optional()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    let (
        reason,
        commitment,
        outbox_id,
        encrypted_output,
        ack_digest,
        existing_usage,
        existing_disposition,
        existing_application_key,
    ) = match receipt {
        Some(row) => {
            let reason = decode_unknown_reason(row.reason)?;
            if !matches!(row.disposition, 1..=3) {
                return Err(ProviderExecutionError::JournalCorrupt);
            }
            let output = row
                .output
                .clone()
                .map(
                    |(key_id, version, nonce, ciphertext, len, digest, authority, generation)| {
                        let runtime_authority: [u8; 16] = unknown_fixed_bytes(authority)?;
                        let database_generation = unknown_positive_u64(generation)?;
                        if runtime_authority != attempt.runtime_authority_id
                            || database_generation != attempt.database_generation
                        {
                            return Err(ProviderExecutionError::JournalCorrupt);
                        }
                        let key = ProviderJournalKeyBinding::new(
                            unknown_fixed_bytes(key_id)?,
                            unknown_positive_u64(version)?,
                            runtime_authority,
                            database_generation,
                        )
                        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
                        Ok::<_, ProviderExecutionError>((
                            key,
                            ProviderEncryptedPayload::new(
                                unknown_fixed_bytes(nonce)?,
                                ciphertext,
                                unknown_nonnegative_u64(len)?,
                                unknown_fixed_bytes(digest)?,
                            )
                            .map_err(|_| ProviderExecutionError::JournalCorrupt)?,
                        ))
                    },
                )
                .transpose()?;
            let id = row.outbox_id.map(unknown_fixed_bytes).transpose()?;
            if id.is_some() != row.application_key.is_some()
                || row.application_key.as_ref().is_some_and(String::is_empty)
            {
                return Err(ProviderExecutionError::JournalCorrupt);
            }
            let digest: [u8; 32] = unknown_fixed_bytes(row.commitment)?;
            let stored_ack = row.ack.map(unknown_fixed_bytes).transpose()?;
            match (id, stored_ack) {
                (Some(outbox_id), acknowledgement) => {
                    if !validate_unknown_terminal_outbox_ack(
                        connection,
                        outbox_id,
                        *attempt.dispatch_attempt_id.as_bytes(),
                        digest,
                        acknowledgement,
                    )? {
                        return Err(ProviderExecutionError::JournalCorrupt);
                    }
                }
                (None, None) => {}
                (None, Some(_)) => return Err(ProviderExecutionError::JournalCorrupt),
            }
            if let Some((key_id, key_version, ..)) = row.output.as_ref() {
                let matches_terminal: bool = connection
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM provider_stream_journal
                     WHERE dispatch_attempt_id=?1 AND sequence=?2 AND terminal=1
                       AND key_id=?3 AND key_version=?4)",
                        params![
                            attempt.dispatch_attempt_id.as_bytes().as_slice(),
                            execution_i64(unknown_nonnegative_u64(row.terminal_sequence)?)?,
                            key_id,
                            key_version
                        ],
                        |item| item.get(0),
                    )
                    .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
                if !matches_terminal {
                    return Err(ProviderExecutionError::JournalCorrupt);
                }
            }
            let usage = match (
                row.usage_present,
                row.input,
                row.output_tokens,
                row.cached,
                row.reasoning,
            ) {
                (0, None, None, None, None)
                    if reason == ProviderUnknownAccountingReason::UsageUnavailable =>
                {
                    None
                }
                (1, Some(input), Some(output), Some(cached), Some(reasoning))
                    if reason != ProviderUnknownAccountingReason::UsageUnavailable =>
                {
                    Some(
                        runne_provider::ProviderUsage::new(
                            unknown_nonnegative_u64(input)?,
                            unknown_nonnegative_u64(output)?,
                            unknown_nonnegative_u64(cached)?,
                            unknown_nonnegative_u64(reasoning)?,
                        )
                        .map_err(|_| ProviderExecutionError::JournalCorrupt)?,
                    )
                }
                _ => return Err(ProviderExecutionError::JournalCorrupt),
            };
            let disposition = match row.disposition {
                1 => runne_provider::ProviderTerminalDisposition::Completed,
                2 => runne_provider::ProviderTerminalDisposition::RemoteFailed,
                3 => runne_provider::ProviderTerminalDisposition::RemoteIncomplete,
                _ => return Err(ProviderExecutionError::JournalCorrupt),
            };
            (
                Some(reason),
                Some(digest),
                id,
                output.map(|(_, payload)| payload),
                stored_ack,
                usage,
                Some(disposition),
                row.application_key,
            )
        }
        None => (None, None, None, None, None, None, None, None),
    };
    let mut digest = Sha256::new();
    digest.update(b"GOCODE_PROVIDER_UNKNOWN_CURRENT_FACTS_V1\0");
    digest.update(taskrun.version.to_be_bytes());
    digest.update(conversation.current_version.to_be_bytes());
    digest.update(attempt.state.to_be_bytes());
    digest.update([u8::from(grant_active)]);
    digest.update([u8::from(current_writer_matches)]);
    digest.update([u8::from(current_generation_matches)]);
    if let Some(value) = grant_digest {
        digest.update(value);
    }
    if let Some(value) = commitment {
        digest.update(value);
    }
    if let Some(value) = ack_digest {
        digest.update(value);
    }
    if let Some(value) = existing_application_key.as_ref() {
        digest.update(value.as_bytes());
    }
    let current_source_state_digest = digest.finalize().into();
    Ok(ProviderUnknownTerminalCurrentFacts {
        current_source_state_digest,
        taskrun_stream_version: taskrun.version,
        conversation_stream_version: conversation.current_version,
        authority_revision,
        grant_digest,
        grant_active,
        source_state,
        output_publication_allowed: source_state == ProviderUnknownSourceState::Running
            && taskrun.active_attempt == Some(taskrun_attempt_id)
            && grant_active
            && current_writer_matches
            && current_generation_matches,
        existing_outbox_digest: commitment,
        existing_outbox_id: outbox_id,
        existing_application_idempotency_key: existing_application_key,
        existing_application_ack_digest: ack_digest,
        existing_unknown_reason: reason,
        existing_unknown_usage: existing_usage,
        existing_unknown_disposition: existing_disposition,
        existing_unknown_commitment: commitment,
        existing_completed_output: encrypted_output,
    })
}

include!("remote_terminal_unknown_current_receipt.rs");
