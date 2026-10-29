type RemoteAccountingProjectionRow = (
    Vec<u8>,
    i64,
    i64,
    i64,
    i64,
    i64,
    String,
    Vec<u8>,
    String,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
    i64,
    String,
);
type BudgetReservationRow = (i64, Vec<u8>, i64, i64, Option<i64>, Option<i64>);
type AdmissionBudgetRow = (Vec<u8>, Vec<u8>, i64, i64, i64);

fn remote_accounting_projection(
    transaction: &Transaction<'_>,
    record: &runne_application::provider::ProviderRemoteAttemptRecord,
    fact: Option<&runne_application::provider::ProviderRemoteAuthenticatedTerminalFact>,
    authenticator: Option<&dyn runne_application::provider::ProviderRemoteFactAuthenticator>,
) -> Result<runne_application::provider::ProviderRemoteAccountingProjection, ProviderExecutionError>
{
    use runne_application::provider::ProviderRemoteAccountingProjection as Projection;
    use runne_provider::{ProviderRemoteResponseStatus as Status, ProviderUsage};

    let Some(fact) = fact else {
        return if record.terminal.is_some() {
            Ok(Projection::Unknown)
        } else {
            remote_accounting_unknown(transaction, record)
        };
    };
    let terminal_status = terminal_status_code(fact.status())?;
    let usage = match fact.status() {
        Status::Completed { usage }
        | Status::Failed { usage, .. }
        | Status::Incomplete { usage, .. }
        | Status::Cancelled { usage } => *usage,
        Status::Pending | Status::Unknown => return Err(ProviderExecutionError::JournalCorrupt),
    };
    let Some(usage) = usage else {
        return remote_accounting_unknown(transaction, record);
    };
    let Some(authenticator) = authenticator else {
        return Ok(Projection::Unknown);
    };

    let row: Option<RemoteAccountingProjectionRow> = transaction
        .query_row(
            "SELECT f.pricing_revision_digest,f.input_tokens,f.output_tokens,
                        f.cached_input_tokens,f.reasoning_output_tokens,f.charge_micros,
                        f.currency,f.settlement_digest,d.provider_idempotency_key,
                        a.token_reservation_id,a.cost_reservation_id,a.requested_input_tokens,
                        a.requested_output_tokens,a.max_cost_micros,a.currency
                 FROM provider_accounting_settlements f
                 JOIN provider_dispatch_attempts d ON d.attempt_id=f.dispatch_attempt_id
                 JOIN provider_execution_admissions a
                   ON a.provider_idempotency_key=d.provider_idempotency_key
                 WHERE f.dispatch_attempt_id=?1",
            [record
                .request
                .binding
                .dispatch_attempt_id
                .as_bytes()
                .as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let Some(row) = row else {
        return remote_accounting_unknown(transaction, record);
    };
    let bound_usage = ProviderUsage::new(
        u64::try_from(row.1).map_err(|_| ProviderExecutionError::JournalCorrupt)?,
        u64::try_from(row.2).map_err(|_| ProviderExecutionError::JournalCorrupt)?,
        u64::try_from(row.3).map_err(|_| ProviderExecutionError::JournalCorrupt)?,
        u64::try_from(row.4).map_err(|_| ProviderExecutionError::JournalCorrupt)?,
    )
    .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    let charge = u64::try_from(row.5).map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    if bound_usage != usage
        || row.0.as_slice() != record.request.binding.pricing_digest.as_slice()
        || row.6 != row.14
        || record
            .terminal
            .as_ref()
            .is_some_and(|terminal| terminal.disposition != terminal_status)
    {
        crate::store::test_support_diagnostics::record("finance.usage_binding");
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    let reservations: Vec<BudgetReservationRow> = {
        let mut statement = transaction
            .prepare(
                "SELECT dimension,reservation_id,amount,state,settled_amount,released_at
                 FROM provider_budget_reservations WHERE provider_idempotency_key=?1
                 ORDER BY dimension",
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        statement
            .query_map([row.8.as_str()], |entry| {
                Ok((
                    entry.get(0)?,
                    entry.get(1)?,
                    entry.get(2)?,
                    entry.get(3)?,
                    entry.get(4)?,
                    entry.get(5)?,
                ))
            })
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?
    };
    if reservations.len() != 2
        || reservations[0].0 != 1
        || reservations[1].0 != 2
        || reservations
            .iter()
            .any(|(_, _, amount, state, settled, released)| {
                *state != 2 || settled.is_none() || released.is_none() || *amount < 0
            })
        || reservations[0].1.as_slice() != row.9.as_slice()
        || reservations[1].1.as_slice() != row.10.as_slice()
        || reservations[0].4
            != Some(
                i64::try_from(usage.total_tokens())
                    .map_err(|_| ProviderExecutionError::JournalCorrupt)?,
            )
        || reservations[1].4
            != Some(i64::try_from(charge).map_err(|_| ProviderExecutionError::JournalCorrupt)?)
        || usage.total_tokens() > u64::try_from(reservations[0].2).unwrap_or_default()
        || charge > u64::try_from(reservations[1].2).unwrap_or_default()
        || u64::try_from(row.11).ok().and_then(|input| {
            u64::try_from(row.12)
                .ok()
                .and_then(|output| input.checked_add(output))
        }) != Some(u64::try_from(reservations[0].2).unwrap_or_default())
        || u64::try_from(row.13).ok() != Some(u64::try_from(reservations[1].2).unwrap_or_default())
    {
        crate::store::test_support_diagnostics::record("finance.reservations");
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    let digest: [u8; 32] = row
        .7
        .as_slice()
        .try_into()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    let expected = remote_expected_identity(&record.request.binding)?;
    let candidate = runne_application::provider::ProviderRemoteTerminalSettlementDigestCandidate {
        status: terminal_status,
        usage,
        charge_micros: charge,
        currency: &row.6,
        settlement_digest: &digest,
    };
    let valid = record.terminal.is_some()
        && authenticator
            .verify_terminal_settlement_digest(record, &expected, candidate)
            .map_err(|_| {
                crate::store::test_support_diagnostics::record("finance.remote_auth_error");
                ProviderExecutionError::JournalCorrupt
            })?;
    if !valid
        && !verify_stream_accounting_settlement(
            transaction,
            record,
            &expected,
            candidate,
            authenticator,
        )?
    {
        crate::store::test_support_diagnostics::record("finance.digest_mismatch");
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    Ok(Projection::Known {
        input_tokens: usage.input_tokens(),
        output_tokens: usage.output_tokens(),
        cached_input_tokens: usage.cached_input_tokens(),
        reasoning_output_tokens: usage.reasoning_output_tokens(),
        charge_micros: i64::try_from(charge).map_err(|_| ProviderExecutionError::JournalCorrupt)?,
        currency: row.6,
    })
}

include!("remote_terminal_effects_snapshot_accounting_unknown.rs");

fn terminal_status_code(
    status: &runne_provider::ProviderRemoteResponseStatus,
) -> Result<runne_application::provider::ProviderRemoteTerminalDisposition, ProviderExecutionError>
{
    use runne_application::provider::ProviderRemoteTerminalDisposition as Disposition;
    use runne_provider::ProviderRemoteResponseStatus as Status;
    match status {
        Status::Completed { .. } => Ok(Disposition::Completed),
        Status::Failed { .. } => Ok(Disposition::Failed),
        Status::Incomplete { .. } => Ok(Disposition::Incomplete),
        Status::Cancelled { .. } => Ok(Disposition::Cancelled),
        Status::Pending | Status::Unknown => Err(ProviderExecutionError::JournalCorrupt),
    }
}

include!("remote_terminal_effects_snapshot_stream_accounting.rs");
