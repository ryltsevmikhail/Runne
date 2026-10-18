use super::codec::CaptureV1;
use runne_application::ports::{EventStoreError, TaskRunAssignmentIdentity};
use rusqlite::{Connection, OptionalExtension, params};

pub(super) fn allows_only_exact_reason2_claim_stop(
    connection: &Connection,
    identity: &TaskRunAssignmentIdentity,
    record: &CaptureV1,
) -> Result<bool, EventStoreError> {
    if record.taskrun_id != *identity.taskrun_id.as_bytes()
        || record.attempt_id != *identity.attempt_id.as_bytes()
        || record.fence != identity.fence.0
    {
        return Ok(false);
    }
    let bytes = super::codec::encode(record).map_err(|_| EventStoreError::CorruptData)?;
    let capture_digest =
        super::codec::binding_digest(&bytes).map_err(|_| EventStoreError::CorruptData)?;
    let foreign_stop: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM x2_permission_stop
             WHERE taskrun_id=?1 AND attempt_id!=?2)",
            params![
                identity.taskrun_id.as_bytes(),
                identity.attempt_id.as_bytes()
            ],
            |row| row.get(0),
        )
        .map_err(|_| EventStoreError::CorruptData)?;
    if foreign_stop {
        return Ok(false);
    }
    let stop: Option<(Vec<u8>, i64, i64, Vec<u8>)> = connection
        .query_row(
            "SELECT binding_digest,reason,observed_version,event_id FROM x2_permission_stop
             WHERE taskrun_id=?1 AND attempt_id=?2",
            params![
                identity.taskrun_id.as_bytes(),
                identity.attempt_id.as_bytes()
            ],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    let Some((digest, reason, version, event_id)) = stop else {
        return Ok(true);
    };
    if digest.as_slice() != capture_digest.as_slice() || reason != 2 {
        return Ok(false);
    }
    let Some(expected_version) = i64::try_from(record.claim_stream_version).ok() else {
        return Ok(false);
    };
    let Some(fence) = i64::try_from(identity.fence.0).ok() else {
        return Ok(false);
    };
    let claim: Option<(i64, Vec<u8>)> = connection
        .query_row(
            "SELECT new_version,started_event_id FROM taskrun_claim_receipts
             WHERE taskrun_id=?1 AND attempt_id=?2 AND fence=?3",
            params![
                identity.taskrun_id.as_bytes(),
                identity.attempt_id.as_bytes(),
                fence
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| EventStoreError::CorruptData)?;
    let Some((claim_version, started_event_id)) = claim else {
        return Ok(false);
    };
    if version != expected_version
        || claim_version != expected_version
        || event_id != started_event_id
    {
        return Ok(false);
    }
    Ok(super::stop::stop_reason(
        connection,
        identity.taskrun_id.as_bytes(),
        identity.attempt_id.as_bytes(),
        &capture_digest,
    )? == Some(2))
}
