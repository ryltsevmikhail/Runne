use runne_application::provider::ProviderTerminalApplicationKind;
fn verify_stream_accounting_settlement(
    transaction: &Transaction<'_>,
    record: &runne_application::provider::ProviderRemoteAttemptRecord,
    expected: &runne_provider::ProviderRecoveryAttemptIdentity,
    candidate: runne_application::provider::ProviderRemoteTerminalSettlementDigestCandidate<'_>,
    authenticator: &dyn runne_application::provider::ProviderRemoteFactAuthenticator,
) -> Result<bool, ProviderExecutionError> {
    let attempt = load_execution_attempt(transaction, record.request.binding.dispatch_attempt_id)?;
    let rows: Vec<(i64, Vec<u8>, i64)> = {
        let mut statement = transaction
            .prepare(
                "SELECT k.application_kind,o.settlement_digest,o.terminal_sequence
             FROM provider_terminal_outbox o
             JOIN provider_terminal_application_kinds k USING(dispatch_attempt_id,outbox_id)
             WHERE o.dispatch_attempt_id=?1",
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        statement
            .query_map([attempt.dispatch_attempt_id.as_bytes().as_slice()], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?
            .collect::<rusqlite::Result<_>>()
            .map_err(|_| ProviderExecutionError::JournalCorrupt)?
    };
    let [(kind, digest, sequence)] = rows.as_slice() else {
        crate::store::test_support_diagnostics::record("finance.stream_outbox");
        return Ok(false);
    };
    if digest.as_slice() != candidate.settlement_digest {
        crate::store::test_support_diagnostics::record("finance.stream_outbox");
        return Ok(false);
    }
    let kind = match kind {
        1 => ProviderTerminalApplicationKind::TextGeneration,
        2 => ProviderTerminalApplicationKind::ToolProposal,
        _ => return Err(ProviderExecutionError::JournalCorrupt),
    };
    let journal = load_encrypted_events_in_transaction(transaction, &attempt)?;
    if journal
        .last()
        .map(|row| (row.sequence as i64, row.terminal))
        != Some((*sequence, true))
    {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    authenticator
        .verify_stream_settlement_digest(record, expected, candidate, &journal, kind)
        .map_err(|_| {
            crate::store::test_support_diagnostics::record("finance.stream_auth_error");
            ProviderExecutionError::JournalCorrupt
        })
}

fn authenticate_stream_projection(
    transaction: &Transaction<'_>,
    record: &runne_application::provider::ProviderRemoteAttemptRecord,
    authenticator: Option<&dyn runne_application::provider::ProviderRemoteFactAuthenticator>,
) -> Result<
    Option<runne_application::provider::ProviderRemoteAuthenticatedTerminalFact>,
    ProviderExecutionError,
> {
    let Some(authenticator) = authenticator else {
        return Ok(None);
    };
    let rows: Vec<i64> = {
        let mut statement=transaction.prepare("SELECT k.application_kind FROM provider_terminal_outbox o JOIN provider_terminal_application_kinds k USING(dispatch_attempt_id,outbox_id) WHERE o.dispatch_attempt_id=?1")
            .map_err(|_|ProviderExecutionError::StoreUnavailable)?;
        statement
            .query_map(
                [record
                    .request
                    .binding
                    .dispatch_attempt_id
                    .as_bytes()
                    .as_slice()],
                |r| r.get(0),
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?
            .collect::<rusqlite::Result<_>>()
            .map_err(|_| ProviderExecutionError::JournalCorrupt)?
    };
    let [kind] = rows.as_slice() else {
        return Ok(None);
    };
    let kind = match kind {
        1 => ProviderTerminalApplicationKind::TextGeneration,
        2 => ProviderTerminalApplicationKind::ToolProposal,
        _ => return Err(ProviderExecutionError::JournalCorrupt),
    };
    let attempt = load_execution_attempt(transaction, record.request.binding.dispatch_attempt_id)?;
    let journal = load_encrypted_events_in_transaction(transaction, &attempt)?;
    authenticator
        .authenticate_stream_terminal(
            record,
            &remote_expected_identity(&record.request.binding)?,
            &journal,
            kind,
        )
        .map_err(|_| ProviderExecutionError::JournalCorrupt)
}

fn stream_local_disposition(
    transaction: &Transaction<'_>,
    record: &runne_application::provider::ProviderRemoteAttemptRecord,
    fact: Option<&runne_application::provider::ProviderRemoteAuthenticatedTerminalFact>,
) -> Result<runne_application::provider::ProviderRemoteLocalDisposition, ProviderExecutionError> {
    use runne_application::provider::ProviderRemoteLocalDisposition as Local;
    let Some(output) = fact.and_then(|f| f.output_digest()) else {
        return Ok(Local::Pending);
    };
    let projected = classify_stream_output(
        transaction,
        record.request.binding.dispatch_attempt_id.as_bytes(),
        output,
    )?;
    if stream_cancel_projection::proven(transaction, record)? {
        return Ok(Local::AcceptedCancellationAfterTerminal);
    }
    if projected == Local::Unknown {
        stream_text_projection::classify(transaction, record, output)
    } else {
        Ok(projected)
    }
}

type StreamAckRow = (Vec<u8>, i64, Option<Vec<u8>>, bool);

fn classify_stream_output(
    transaction: &Transaction<'_>,
    dispatch: &[u8; 16],
    output: &[u8; 32],
) -> Result<runne_application::provider::ProviderRemoteLocalDisposition, ProviderExecutionError> {
    use runne_application::provider::ProviderRemoteLocalDisposition as Local;
    let rows: Vec<StreamAckRow> = {
        let mut statement=transaction.prepare("SELECT plaintext_digest,state,receipt_digest,applied_at IS NOT NULL FROM provider_terminal_outbox WHERE dispatch_attempt_id=?1")
            .map_err(|_|ProviderExecutionError::StoreUnavailable)?;
        statement
            .query_map([dispatch.as_slice()], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?
            .collect::<rusqlite::Result<_>>()
            .map_err(|_| ProviderExecutionError::JournalCorrupt)?
    };
    let [(digest, state, receipt, applied)] = rows.as_slice() else {
        return Err(ProviderExecutionError::JournalCorrupt);
    };
    if digest.as_slice() != output {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    Ok(if *state == 2 && *applied {
        let receipt = receipt
            .as_ref()
            .ok_or(ProviderExecutionError::JournalCorrupt)?;
        if crate::store::text_receipt_helpers::stream_projection::stream_completion_published(
            transaction,
            dispatch,
            receipt,
            output,
        )
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?
        {
            Local::OutputApplied
        } else {
            Local::Unknown
        }
    } else {
        Local::Pending
    })
}

#[cfg(test)]
#[path = "remote_terminal_effects_snapshot_stream_tests.rs"]
mod stream_projection_tests;

#[path = "stream_text_projection.rs"]
mod stream_text_projection;

#[path = "stream_cancel_projection.rs"]
mod stream_cancel_projection;
