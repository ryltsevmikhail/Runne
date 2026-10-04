use std::path::Path;

use rusqlite::{Connection, params};

/// Copies real stored conversation/taskrun event history into a released V18
/// schema so V19 rollback fixtures do not inherit later schema objects.
pub fn copy_conversation_and_taskrun_history(
    destination: &Connection,
    source_database: &Path,
    conversation_id: &[u8],
    taskrun_id: &[u8],
) -> rusqlite::Result<()> {
    destination.execute_batch("PRAGMA foreign_keys=OFF;")?;
    let copy: rusqlite::Result<()> = (|| {
        destination.execute(
            "ATTACH DATABASE ?1 AS x2_current_source",
            [source_database
                .to_str()
                .ok_or(rusqlite::Error::InvalidQuery)?],
        )?;
        destination.execute(
            "INSERT INTO aggregate_streams
             (aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at)
             SELECT aggregate_type, aggregate_id, current_version, last_event_id, last_timestamp, created_at
             FROM x2_current_source.aggregate_streams
             WHERE (aggregate_type=1 AND aggregate_id=?1)
                OR (aggregate_type=2 AND aggregate_id=?2)",
            params![taskrun_id, conversation_id],
        )?;
        destination.execute(
            "INSERT INTO events
             (event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp,
              sensitivity, schema_version, causation_id, command_id, idempotency_key, actor,
              payload, integrity_digest, correlation_id, correlation_type, integrity_profile)
             SELECT event_id, aggregate_type, aggregate_id, sequence, global_position, timestamp,
                    sensitivity, schema_version, causation_id, command_id, idempotency_key, actor,
                    payload, integrity_digest, correlation_id, correlation_type, integrity_profile
             FROM x2_current_source.events
             WHERE (aggregate_type=1 AND aggregate_id=?1)
                OR (aggregate_type=2 AND aggregate_id=?2)",
            params![taskrun_id, conversation_id],
        )?;
        Ok(())
    })();
    let detach = destination.execute_batch("DETACH DATABASE x2_current_source;");
    let restore_foreign_keys = destination.execute_batch("PRAGMA foreign_keys=ON;");
    copy?;
    detach?;
    restore_foreign_keys
}
