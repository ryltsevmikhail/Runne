struct UnknownSourceRows {
    taskrun_id: TaskRunId,
    taskrun_attempt_id: AttemptId,
    conversation_id: ConversationId,
    principal_id: String,
    provider_id: String,
    provider_idempotency_key: String,
    authority_id: [u8; 16],
    authority_revision: u64,
    runtime_authority_id: [u8; 16],
    database_generation: u64,
    runtime_generation: u64,
    fencing_token: u64,
    profile_digest: [u8; 32],
    pricing_revision_digest: [u8; 32],
    currency: String,
    request_digest: [u8; 32],
    token_reservation_id: [u8; 16],
    cost_reservation_id: [u8; 16],
    token_amount: u64,
    cost_amount: u64,
    reservations: [ProviderUnknownReservationSnapshot; 2],
    original_effect: ProviderUnknownCommittedEffectProof,
    original: ProviderUnknownTerminalOriginalBinding,
    current: ProviderUnknownTerminalCurrentFacts,
}

fn load_unknown_snapshot(
    connection: &Connection,
    selector: &ProviderTerminalUnknownSelector,
    proof: &OnlineEffectProofCapabilitySet,
) -> Result<(ProviderUnknownTerminalSnapshot, UnknownSourceRows), ProviderExecutionError> {
    let attempt = load_execution_attempt(connection, selector.attempt_id())?;
    if attempt.fencing_token != selector.fencing_token() || !matches!(attempt.state, 3..=6)
    {
        return Err(ProviderExecutionError::TerminalConflict);
    }
    let rows = crate::store::test_support_diagnostics::on_error(
        "unknown.source_rows",
        load_unknown_source_rows(connection, &attempt, Some(proof)),
    )?;
    let journal = crate::store::test_support_diagnostics::on_error(
        "unknown.journal",
        load_encrypted_events_in_transaction(connection, &attempt),
    )?;
    let terminal = journal
        .iter()
        .find(|row| row.sequence == selector.terminal_sequence() && row.terminal)
        .ok_or(ProviderExecutionError::JournalCorrupt)?;
    let context = ProviderEventJournalContext {
        attempt_id: selector.attempt_id(),
        fencing_token: selector.fencing_token(),
        call_digest_version: terminal.call_digest_version,
        profile_digest: terminal.profile_digest,
        runtime_generation: terminal.runtime_generation,
    };
    let snapshot = crate::store::test_support_diagnostics::on_error(
        "unknown.snapshot_shape",
        ProviderUnknownTerminalSnapshot::from_store_transaction(
            *selector,
            context,
            rows.original.clone(),
            rows.original_effect.clone(),
            rows.current.clone(),
            journal,
        ),
    )?;
    Ok((snapshot, rows))
}

pub(crate) fn load_unknown_effects_snapshot(
    connection: &Connection,
    taskrun_id: TaskRunId,
    taskrun_attempt_id: runne_domain::id::AttemptId,
) -> Result<Option<ProviderUnknownTerminalSnapshot>, ProviderExecutionError> {
    let selected = connection
        .query_row(
            "SELECT a.dispatch_attempt_id,a.fencing_token,r.terminal_sequence
               FROM provider_execution_admissions a
               JOIN provider_unknown_terminal_receipts r
                 ON r.dispatch_attempt_id=a.dispatch_attempt_id
               JOIN provider_dispatch_attempts d
                 ON d.attempt_id=a.dispatch_attempt_id
              WHERE a.taskrun_id=?1 AND a.execution_attempt_id=?2",
            params![
                taskrun_id.as_bytes().as_slice(),
                taskrun_attempt_id.as_bytes().as_slice()
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    let Some((dispatch, fence, sequence)) = selected else {
        return Ok(None);
    };
    let dispatch: [u8; 16] = dispatch
        .try_into()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    let selector = ProviderTerminalUnknownSelector::new(
        DispatchAttemptId::from_bytes(dispatch),
        unknown_positive_u64(sequence)?,
        unknown_positive_u64(fence)?,
    );
    let attempt = load_execution_attempt(connection, selector.attempt_id())?;
    if attempt.fencing_token != selector.fencing_token() {
        return Err(ProviderExecutionError::TerminalConflict);
    }
    let rows = load_unknown_source_rows(connection, &attempt, None)?;
    let journal = load_encrypted_events_in_transaction(connection, &attempt)?;
    let terminal = journal
        .iter()
        .find(|record| record.sequence == selector.terminal_sequence() && record.terminal)
        .ok_or(ProviderExecutionError::JournalCorrupt)?;
    let context = ProviderEventJournalContext {
        attempt_id: selector.attempt_id(),
        fencing_token: selector.fencing_token(),
        call_digest_version: terminal.call_digest_version,
        profile_digest: terminal.profile_digest,
        runtime_generation: terminal.runtime_generation,
    };
    ProviderUnknownTerminalSnapshot::from_store_transaction(
        selector,
        context,
        rows.original,
        rows.original_effect,
        rows.current,
        journal,
    )
    .map(Some)
}

include!("remote_terminal_unknown_source.rs");
include!("remote_terminal_unknown_effect.rs");
include!("remote_terminal_unknown_binding.rs");
include!("remote_terminal_unknown_issuance.rs");
include!("remote_terminal_unknown_begin.rs");
include!("remote_terminal_unknown_history.rs");
include!("remote_terminal_unknown_current.rs");
include!("remote_terminal_unknown_journal.rs");
include!("remote_terminal_unknown_decode.rs");
