type RemoteAccountingProjectionRow = (
    Vec<u8>, i64, i64, i64, i64, i64, String, Vec<u8>, String, Vec<u8>, Vec<u8>, i64, i64, i64, String,
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

    let Some(terminal) = record.terminal.as_ref() else {
        return remote_accounting_unknown(transaction, record);
    };
    let Some(fact) = fact else {
        return Ok(Projection::Unknown);
    };
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
        || terminal.disposition != terminal_status_code(fact.status())?
    {
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
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    let digest: [u8; 32] = row
        .7
        .as_slice()
        .try_into()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    let expected = remote_expected_identity(&record.request.binding)?;
    let valid = authenticator
        .verify_terminal_settlement_digest(
            record,
            &expected,
            runne_application::provider::ProviderRemoteTerminalSettlementDigestCandidate {
                status: terminal.disposition,
                usage,
                charge_micros: charge,
                currency: &row.6,
                settlement_digest: &digest,
            },
        )
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    if !valid {
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

fn remote_accounting_unknown(
    transaction: &Transaction<'_>,
    record: &runne_application::provider::ProviderRemoteAttemptRecord,
) -> Result<runne_application::provider::ProviderRemoteAccountingProjection, ProviderExecutionError>
{
    use runne_application::provider::ProviderRemoteAccountingProjection as Projection;
    let key = record.request.binding.dispatch_attempt_id.as_bytes();
    let has_settlement: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_accounting_settlements WHERE dispatch_attempt_id=?1)",
            [key.as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let admission: Option<AdmissionBudgetRow> = transaction
        .query_row(
            "SELECT a.token_reservation_id,a.cost_reservation_id,
                    a.requested_input_tokens,a.requested_output_tokens,a.max_cost_micros
             FROM provider_dispatch_attempts d JOIN provider_execution_admissions a
               ON a.provider_idempotency_key=d.provider_idempotency_key
             WHERE d.attempt_id=?1",
            [key.as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let reservations: Vec<BudgetReservationRow> = {
        let mut statement = transaction
            .prepare(
                "SELECT b.dimension,b.reservation_id,b.amount,b.state,b.settled_amount,b.released_at
                 FROM provider_budget_reservations b
                 JOIN provider_dispatch_attempts d
                   ON d.provider_idempotency_key=b.provider_idempotency_key
                 JOIN provider_execution_admissions a
                   ON a.provider_idempotency_key=d.provider_idempotency_key
                 WHERE d.attempt_id=?1 ORDER BY b.dimension",
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        statement
            .query_map([key.as_slice()], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            })
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?
    };
    let Some(admission) = admission else {
        return Err(ProviderExecutionError::JournalCorrupt);
    };
    let token_reserve = u64::try_from(admission.2)
        .ok()
        .and_then(|input| {
            u64::try_from(admission.3)
                .ok()
                .and_then(|output| input.checked_add(output))
        })
        .ok_or(ProviderExecutionError::JournalCorrupt)?;
    if has_settlement
        || reservations.len() != 2
        || reservations[0].0 != 1
        || reservations[1].0 != 2
        || reservations[0].1.as_slice() != admission.0.as_slice()
        || reservations[1].1.as_slice() != admission.1.as_slice()
        || u64::try_from(reservations[0].2).ok() != Some(token_reserve)
        || u64::try_from(reservations[1].2).ok() != u64::try_from(admission.4).ok()
        || reservations[0].2 <= 0
        || reservations[1].2 <= 0
        || reservations
            .iter()
            .any(|(_, _, _, state, settled, released)| {
                *state != 1 || settled.is_some() || released.is_some()
            })
    {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    Ok(Projection::Unknown)
}

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
