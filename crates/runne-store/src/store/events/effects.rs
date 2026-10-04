use runne_api::{
    LocalCommandEffectV1, LocalCommandOutcomeV1 as LocalOutcome, LocalCommandStopV1 as LocalStop,
    RemoteCancellationV1 as RemoteCancel, RemoteEffectAvailabilityV1 as RemoteAvailability,
    RemoteEffectCapabilitiesV1, RemoteEffectOutcomeV1 as RemoteOutcome, RemoteEffectV1,
    SuccessorEligibilityV1, TaskRunEffectsV1,
};

type LocalEffectRow = (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    String,
    Option<Vec<u8>>,
    Option<i64>,
    Option<Vec<u8>>,
);

fn load_task_run_effects_from_store(
    store: &StoreTransaction,
    taskrun_id: TaskRunId,
) -> Result<TaskRunEffectsV1, EventStoreError> {
    let mut connection = store
        .inner
        .reader
        .lock()
        .map_err(|_| EventStoreError::Unavailable)?;
    let tx = connection
        .transaction()
        .map_err(map_event_store_read_error)?;
    let snapshot = load_task_run_effects_snapshot_in_transaction(
        &tx,
        &store.runtime_authority_id,
        taskrun_id,
        None,
        None,
        SuccessorEligibilityV1::Blocked,
    )?;
    tx.commit().map_err(map_event_store_read_error)?;
    Ok(snapshot.effects)
}

include!("effects_remote_snapshot.rs");

fn local_effect_row(
    tx: &rusqlite::Transaction<'_>,
    taskrun_id: TaskRunId,
) -> Result<LocalEffectRow, EventStoreError> {
    tx.query_row(
        "SELECT conversation_id,workspace_id,command_digest,state,attempt_id,exit_code,managed_area_identity FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
        [taskrun_id.as_bytes()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
    ).map_err(|_| EventStoreError::CorruptData)
}

fn local_effect_row_optional(
    tx: &rusqlite::Transaction<'_>,
    taskrun_id: TaskRunId,
) -> Result<Option<LocalEffectRow>, EventStoreError> {
    tx.query_row(
        "SELECT conversation_id,workspace_id,command_digest,state,attempt_id,exit_code,managed_area_identity FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
        [taskrun_id.as_bytes()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
    ).optional().map_err(|_| EventStoreError::CorruptData)
}

fn parse_optional_attempt(value: Option<Vec<u8>>) -> Result<Option<AttemptId>, EventStoreError> {
    value
        .map(|bytes| {
            let id = bytes.try_into().map_err(|_| EventStoreError::CorruptData)?;
            Ok(AttemptId::from_bytes(id))
        })
        .transpose()
}

fn latest_validated_attempt(
    _tx: &rusqlite::Transaction<'_>,
    _taskrun_id: TaskRunId,
    taskrun: &runne_domain::task_run::TaskRun,
) -> Result<Option<AttemptId>, EventStoreError> {
    Ok(taskrun.attempt_history().last().copied())
}
