fn find_remote_attempt(
    store: &SqliteProviderExecutionStore,
    taskrun: runne_domain::id::TaskRunId,
    task_attempt: runne_domain::id::AttemptId,
) -> Result<Option<DispatchAttemptId>, ProviderExecutionError> {
    let mut connection = store
        .connection
        .lock()
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let intent_count: i64 = transaction
        .query_row(
            "SELECT COUNT(*) FROM provider_remote_request_intents
             WHERE taskrun_id=?1 AND taskrun_attempt_id=?2",
            rusqlite::params![
                taskrun.as_bytes().as_slice(),
                task_attempt.as_bytes().as_slice()
            ],
            |row| row.get(0),
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if intent_count > 1 {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    let query = format!(
        "SELECT q.dispatch_attempt_id FROM provider_remote_request_intents q
         JOIN provider_remote_response_bindings r USING(dispatch_attempt_id)
         WHERE q.taskrun_id=?1 AND q.taskrun_attempt_id=?2
           AND {SETTLED_REMOTE_ATTEMPT_FILTER}
         ORDER BY q.dispatch_attempt_id LIMIT 129"
    );
    let mut statement = transaction
        .prepare(&query)
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
    if candidate_ids.len() > 1 {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    let mut ids = Vec::new();
    for candidate in candidate_ids {
        let record = read_remote_attempt_in_transaction(&transaction, candidate)?
            .ok_or(ProviderExecutionError::JournalCorrupt)?;
        if !remote_attempt_has_valid_v62_audit(&transaction, &record)? {
            ids.push(candidate);
        }
    }
    transaction
        .commit()
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    Ok(ids.pop())
}

fn remote_attempt_has_valid_v62_audit(
    connection: &rusqlite::Connection,
    record: &runne_application::provider::ProviderRemoteAttemptRecord,
) -> Result<bool, ProviderExecutionError> {
    let binding = &record.request.binding;
    let present: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_remote_terminal_audit_receipts
             WHERE dispatch_attempt_id=?1)",
            [binding.dispatch_attempt_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if !present {
        return Ok(false);
    }
    let response = record
        .response
        .as_ref()
        .ok_or(ProviderExecutionError::JournalCorrupt)?;
    let terminal = record
        .terminal
        .as_ref()
        .ok_or(ProviderExecutionError::JournalCorrupt)?;
    let valid = crate::schema::v62_valid_audit_for_source(
        connection,
        crate::schema::RemoteTerminalSourceMatch {
            dispatch: binding.dispatch_attempt_id.as_bytes(),
            taskrun: binding.taskrun_id.as_bytes(),
            attempt: binding.taskrun_attempt_id.as_bytes(),
            request: binding.request_digest.as_slice(),
            response: response.encrypted_response_id.plaintext_digest().as_slice(),
            artifact: terminal.encrypted_artifact.plaintext_digest().as_slice(),
            status: terminal.disposition.code(),
        },
    )
    .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if !valid {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    Ok(true)
}

fn load_remote_call_digest_version(
    store: &SqliteProviderExecutionStore,
    attempt: DispatchAttemptId,
) -> Result<runne_provider::ProviderCallDigestVersion, ProviderExecutionError> {
    let connection = store
        .connection
        .lock()
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    load_execution_attempt(&connection, attempt).map(|record| record.call_digest_version)
}
