use super::*;
use runne_application::ports::{
    TaskRunAssignmentIdentity, TaskRunExecutionInputError as Error, TaskRunExecutionInputPort,
    TaskRunExecutionInputV2,
};
use rusqlite::TransactionBehavior;

impl TaskRunExecutionInputPort for StoreTransaction {
    fn read_taskrun_execution_input(
        &self,
        identity: TaskRunAssignmentIdentity,
        expected_claim_version: u64,
    ) -> Result<TaskRunExecutionInputV2, Error> {
        let mut reader = self.inner.reader.lock().map_err(|_| Error::Unavailable)?;
        let tx = reader
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| Error::Unavailable)?;
        let version: Option<i64> = tx
            .query_row(
                "SELECT new_version FROM taskrun_claim_receipts WHERE taskrun_id=?1 AND fence=?2 AND attempt_id=?3 AND node_id=?4 AND node_epoch=?5",
                rusqlite::params![identity.taskrun_id.as_bytes(), identity.fence.0 as i64, identity.attempt_id.as_bytes(), uuid::Uuid::parse_str(&identity.node_id.0).map_err(|_| Error::StaleAssignment)?.as_bytes(), identity.node_epoch as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| Error::CorruptData)?;
        let Some(version) = version else {
            return Err(Error::StaleAssignment);
        };
        let version = u64::try_from(version).map_err(|_| Error::CorruptData)?;
        if version != expected_claim_version {
            return Err(Error::StaleVersion);
        }
        let head: i64 = tx
            .query_row(
                "SELECT current_version FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=?1",
                [identity.taskrun_id.as_bytes()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| Error::CorruptData)?
            .ok_or(Error::CorruptData)?;
        if u64::try_from(head).ok() != Some(version) {
            return Err(Error::StaleVersion);
        }
        let occupation: Option<(String, i64)> = tx
            .query_row(
                "SELECT o.state,o.lease_expires_at_ms FROM taskrun_assignment_occupations o JOIN taskrun_assignments a USING(taskrun_id,fence) WHERE o.taskrun_id=?1 AND o.fence=?2 AND o.attempt_id=?3 AND o.node_id=?4 AND o.node_epoch=?5 AND a.attempt_id=o.attempt_id AND a.node_id=o.node_id AND a.node_epoch=o.node_epoch",
                rusqlite::params![identity.taskrun_id.as_bytes(), identity.fence.0 as i64, identity.attempt_id.as_bytes(), uuid::Uuid::parse_str(&identity.node_id.0).map_err(|_| Error::StaleAssignment)?.as_bytes(), identity.node_epoch as i64],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| Error::CorruptData)?;
        let now: i64 = tx
            .query_row(
                "SELECT CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)",
                [],
                |row| row.get(0),
            )
            .map_err(|_| Error::Unavailable)?;
        if !matches!(occupation, Some((ref state, expiry)) if state == "active" && expiry > now) {
            return Err(Error::StaleAssignment);
        }
        super::taskrun_claim::verify_active_assignment(&tx, &identity).map_err(
            |error| match error {
                runne_application::ports::TaskRunClaimError::NotQueued => Error::NotExecutable,
                _ => Error::CorruptData,
            },
        )?;
        let payload: Vec<u8> = tx
            .query_row(
                "SELECT payload FROM events WHERE aggregate_type=1 AND aggregate_id=?1 AND sequence=1",
                [identity.taskrun_id.as_bytes()],
                |row| row.get(0),
            )
            .map_err(|_| Error::CorruptData)?;
        let event = TaskRunEventCodec
            .decode(&payload)
            .map_err(|_| Error::CorruptData)?;
        let result = match event {
            TaskRunEvent::TaskRunSubmitted {
                conversation_id,
                workspace_id,
                input,
            } => TaskRunExecutionInputV2 {
                taskrun_id: identity.taskrun_id,
                attempt_id: identity.attempt_id,
                stream_version: version,
                conversation_id,
                workspace_id,
                input,
            },
            TaskRunEvent::TaskRunCreated => return Err(Error::UnsupportedInput),
            _ => return Err(Error::CorruptData),
        };
        tx.commit().map_err(|_| Error::Unavailable)?;
        Ok(result)
    }
}
