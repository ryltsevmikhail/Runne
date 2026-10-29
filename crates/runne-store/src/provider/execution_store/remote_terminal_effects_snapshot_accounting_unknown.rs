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
