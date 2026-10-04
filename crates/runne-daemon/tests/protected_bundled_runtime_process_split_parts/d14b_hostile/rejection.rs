use super::*;

pub(super) fn assert_taskrun_rejection_reason(
    database: &Path,
    task_run_id: runne_runtime_client::CanonicalId,
) {
    use runne_store::codec::{StoreCodec, TaskRunEventCodec};
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("TaskRun event reader");
    let task_run_bytes: [u8; 16] = hex::decode(task_run_id.to_string().replace('-', ""))
        .expect("TaskRun UUID bytes")
        .try_into()
        .expect("TaskRun UUID width");
    let payload: Vec<u8> = connection
        .query_row(
            "SELECT payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1
             ORDER BY sequence DESC LIMIT 1",
            [task_run_bytes.as_slice()],
            |row| row.get(0),
        )
        .expect("TaskRun terminal event");
    assert!(matches!(
        TaskRunEventCodec.decode(&payload),
        Ok(runne_domain::task_run::TaskRunEvent::TaskRunFailed { ref reason })
            if reason == "provider_execution_rejected"
    ));
}

pub(super) fn assert_zero_dispatch_attempts(database: &Path) {
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("daemon database reader");
    let attempts: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM provider_dispatch_attempts",
            [],
            |row| row.get(0),
        )
        .expect("dispatch attempt count");
    assert_eq!(
        attempts, 0,
        "exec in a hostile workspace issues no dispatch"
    );
}
