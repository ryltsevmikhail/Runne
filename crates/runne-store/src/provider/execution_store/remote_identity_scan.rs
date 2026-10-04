include!("remote_identity_scan_filter.rs");

fn scan_remote_attempts(
    store: &SqliteProviderExecutionStore,
    after: Option<DispatchAttemptId>,
    limit: usize,
) -> Result<runne_application::provider::ProviderRemoteAttemptPage, ProviderExecutionError> {
    if limit == 0 || limit > 128 {
        return Err(ProviderExecutionError::StoreUnavailable);
    }
    let mut connection = store
        .connection
        .lock()
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let query = format!(
        "SELECT q.dispatch_attempt_id FROM provider_remote_request_intents q
         JOIN provider_remote_response_bindings r USING(dispatch_attempt_id)
         WHERE (?1 IS NULL OR q.dispatch_attempt_id>?1)
           AND {SETTLED_REMOTE_ATTEMPT_FILTER}
         ORDER BY q.dispatch_attempt_id LIMIT ?2"
    );
    let mut statement = transaction
        .prepare(&query)
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let rows = statement
        .query_map(
            rusqlite::params![after.map(|value| value.as_bytes().to_vec()), limit as i64],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let candidate_ids = rows
        .map(|row| {
            let bytes = row.map_err(|_| ProviderExecutionError::StoreUnavailable)?;
            let bytes: [u8; 16] = bytes
                .try_into()
                .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
            Ok(DispatchAttemptId::from_bytes(bytes))
        })
        .collect::<Result<Vec<_>, ProviderExecutionError>>()?;
    drop(statement);
    let mut attempts = Vec::with_capacity(candidate_ids.len());
    for candidate in &candidate_ids {
        let record = read_remote_attempt_in_transaction(&transaction, *candidate)?
            .ok_or(ProviderExecutionError::JournalCorrupt)?;
        if !remote_attempt_has_valid_v62_audit(&transaction, &record)? {
            attempts.push(*candidate);
        }
    }
    let next_after = candidate_ids.last().copied();
    let reached_end = candidate_ids.len() < limit;
    transaction
        .commit()
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    Ok(runne_application::provider::ProviderRemoteAttemptPage {
        attempts,
        next_after,
        reached_end,
    })
}
