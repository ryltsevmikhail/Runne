use super::parse_helpers::map_event_store_read_error;
use super::*;
use runne_application::ports::{
    TaskRunCancellationScanner, TaskRunQueueCandidate, TaskRunQueueScanPage,
    TaskRunQueueScanRequest,
};
use rusqlite::TransactionBehavior;

impl TaskRunCancellationScanner for StoreTransaction {
    fn scan_pending_taskrun_cancellations(
        &self,
        request: TaskRunQueueScanRequest,
    ) -> Result<TaskRunQueueScanPage, EventStoreError> {
        let mut reader = self
            .inner
            .reader
            .lock()
            .map_err(|_| EventStoreError::Unavailable)?;
        let tx = reader
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(map_event_store_read_error)?;
        let cursor = request.after().map(|id| id.as_bytes().to_vec());
        let mut statement = tx
            .prepare(
                "SELECT aggregate_id,current_version FROM aggregate_streams
             WHERE aggregate_type=1 AND (?1 IS NULL OR aggregate_id>?1)
             ORDER BY aggregate_id ASC LIMIT ?2",
            )
            .map_err(map_event_store_read_error)?;
        let rows = statement
            .query_map(params![cursor, (request.limit() + 1) as i64], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(map_event_store_read_error)?;
        let rows: Vec<(Vec<u8>, i64)> = rows
            .collect::<Result<_, _>>()
            .map_err(map_event_store_read_error)?;
        let reached_end = rows.len() <= request.limit();
        let examined = rows.len().min(request.limit());
        let next_cursor = rows
            .get(examined.saturating_sub(1))
            .map(|row| TaskRunId::from_bytes(row.0.as_slice().try_into().unwrap_or([0; 16])))
            .or(request.after());
        let mut candidates = Vec::new();
        for (aggregate, version) in rows.into_iter().take(request.limit()) {
            let taskrun_id = TaskRunId::from_bytes(
                aggregate
                    .try_into()
                    .map_err(|_| EventStoreError::CorruptData)?,
            );
            let version = u64::try_from(version).map_err(|_| EventStoreError::CorruptData)?;
            if version == 0 {
                return Err(EventStoreError::CorruptData);
            }
            let (sequence, payload): (i64, Vec<u8>) = tx.query_row(
                "SELECT sequence,payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1 ORDER BY sequence DESC LIMIT 1",
                [taskrun_id.as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).map_err(map_event_store_read_error)?;
            if u64::try_from(sequence).ok() != Some(version) {
                return Err(EventStoreError::CorruptData);
            }
            let event = TaskRunEventCodec
                .decode(&payload)
                .map_err(|_| EventStoreError::CorruptData)?;
            if matches!(
                event,
                runne_domain::task_run::TaskRunEvent::CancellationRequested
            ) {
                candidates.push(TaskRunQueueCandidate {
                    taskrun_id,
                    current_version: version,
                });
            }
        }
        drop(statement);
        tx.commit().map_err(map_event_store_read_error)?;
        Ok(TaskRunQueueScanPage {
            candidates,
            next_cursor,
            reached_end,
            examined,
        })
    }
}
