fn find_remote_attempt_history(
    store: &SqliteProviderExecutionStore,
    taskrun: runne_domain::id::TaskRunId,
    task_attempt: runne_domain::id::AttemptId,
) -> Result<Option<DispatchAttemptId>, ProviderExecutionError> {
    let connection = store
        .connection
        .lock()
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let mut statement = connection
        .prepare(
            "SELECT dispatch_attempt_id FROM provider_remote_request_intents
             WHERE taskrun_id=?1 AND taskrun_attempt_id=?2
             ORDER BY dispatch_attempt_id LIMIT 2",
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let rows = statement
        .query_map(
            rusqlite::params![
                taskrun.as_bytes().as_slice(),
                task_attempt.as_bytes().as_slice()
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let mut ids = rows
        .map(|row| {
            let bytes = row.map_err(|_| ProviderExecutionError::StoreUnavailable)?;
            let bytes: [u8; 16] = bytes
                .try_into()
                .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
            Ok(DispatchAttemptId::from_bytes(bytes))
        })
        .collect::<Result<Vec<_>, ProviderExecutionError>>()?;
    if ids.len() > 1 {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    Ok(ids.pop())
}

fn load_remote_attempt_history(
    store: &SqliteProviderExecutionStore,
    taskrun: runne_domain::id::TaskRunId,
    task_attempt: runne_domain::id::AttemptId,
) -> Result<Option<runne_application::provider::ProviderRemoteAttemptRecord>, ProviderExecutionError>
{
    let mut connection = store
        .connection
        .lock()
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let tx = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let mut statement = tx
        .prepare(
            "SELECT dispatch_attempt_id FROM provider_remote_request_intents
             WHERE taskrun_id=?1 AND taskrun_attempt_id=?2
             ORDER BY dispatch_attempt_id LIMIT 2",
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let rows = statement
        .query_map(
            rusqlite::params![
                taskrun.as_bytes().as_slice(),
                task_attempt.as_bytes().as_slice()
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let mut ids = rows
        .map(|row| {
            let bytes = row.map_err(|_| ProviderExecutionError::StoreUnavailable)?;
            let bytes: [u8; 16] = bytes
                .try_into()
                .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
            Ok(DispatchAttemptId::from_bytes(bytes))
        })
        .collect::<Result<Vec<_>, ProviderExecutionError>>()?;
    if ids.len() > 1 {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    let record = match ids.pop() {
        Some(attempt) => {
            let record = read_remote_attempt_in_transaction(&tx, attempt)?
                .ok_or(ProviderExecutionError::JournalCorrupt)?;
            let binding = &record.request.binding;
            if binding.taskrun_id != taskrun
                || binding.taskrun_attempt_id != task_attempt
                || binding.dispatch_attempt_id != attempt
            {
                return Err(ProviderExecutionError::JournalCorrupt);
            }
            if crate::schema::read_authority_id(&tx)
                .map_err(|_| ProviderExecutionError::StoreUnavailable)?
                != Some(binding.runtime_authority_id)
                || crate::schema::read_event_log_lineage_id(&tx)
                    .map_err(|_| ProviderExecutionError::StoreUnavailable)?
                    .is_none()
            {
                return Err(ProviderExecutionError::TerminalConflict);
            }
            validate_historical_response_binding(&tx, binding, record.request.key, store.now())
                .map_err(|_| ProviderExecutionError::TerminalConflict)?;
            let authority = runne_application::ports::RuntimeAuthorityId(
                binding
                    .runtime_authority_id
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
            );
            crate::store::taskrun_submit_origin::verify_remote_terminal_taskrun_source(
                &tx,
                attempt.as_bytes(),
                &authority,
            )
            .map_err(|_| ProviderExecutionError::TerminalConflict)?;
            Some(record)
        }
        None => None,
    };
    drop(statement);
    tx.commit()
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    Ok(record)
}
