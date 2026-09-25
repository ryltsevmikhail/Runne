use super::parse_helpers::map_event_store_read_error;
use super::*;
use runne_application::ports::{
    TaskRunQueueCandidate, TaskRunQueueScanPage, TaskRunQueueScanRequest, TaskRunQueueScanner,
};
use rusqlite::TransactionBehavior;

impl TaskRunQueueScanner for StoreTransaction {
    fn scan_queued_task_runs(
        &self,
        request: TaskRunQueueScanRequest,
    ) -> Result<TaskRunQueueScanPage, EventStoreError> {
        let mut connection = self
            .inner
            .reader
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(map_event_store_read_error)?;
        let cursor = request.after().map(|id| id.as_bytes().to_vec());
        let mut statement = tx
            .prepare(
                "SELECT aggregate_id FROM aggregate_streams
                 WHERE aggregate_type = ?1 AND (?2 IS NULL OR aggregate_id > ?2)
                 ORDER BY aggregate_id ASC LIMIT ?3",
            )
            .map_err(map_event_store_read_error)?;
        let rows = statement
            .query_map(
                params![
                    CORRELATION_TYPE_TASK_RUN,
                    cursor,
                    (request.limit() + 1) as i64
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .map_err(map_event_store_read_error)?;
        let mut ids = rows
            .map(|row| {
                let bytes = row.map_err(map_event_store_read_error)?;
                let bytes: [u8; 16] = bytes.try_into().map_err(|_| EventStoreError::CorruptData)?;
                Ok(TaskRunId::from_bytes(bytes))
            })
            .collect::<Result<Vec<_>, EventStoreError>>()?;
        let reached_end = ids.len() <= request.limit();
        ids.truncate(request.limit());
        drop(statement);
        let next_cursor = ids.last().copied().or(request.after());
        let mut candidates = Vec::new();
        for taskrun_id in &ids {
            let verified =
                super::taskrun_claim::stream_validate::verify_stream(&tx, *taskrun_id, None)
                    .map_err(map_claim_validation_error)?;
            if verified.is_v2_submission
                && verified.has_immutable_input
                && verified.state == runne_domain::task_run::TaskRunState::Queued
            {
                candidates.push(TaskRunQueueCandidate {
                    taskrun_id: *taskrun_id,
                    current_version: verified.version,
                });
            }
        }
        tx.commit().map_err(map_event_store_read_error)?;
        Ok(TaskRunQueueScanPage {
            candidates,
            next_cursor,
            reached_end,
            examined: ids.len(),
        })
    }
}

fn map_claim_validation_error(
    error: runne_application::ports::TaskRunClaimError,
) -> EventStoreError {
    match error {
        runne_application::ports::TaskRunClaimError::Unavailable => EventStoreError::Unavailable,
        _ => EventStoreError::CorruptData,
    }
}
