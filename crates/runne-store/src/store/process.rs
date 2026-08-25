use super::*;

/// Durable owner-bound process metadata without native handles or raw paths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableProcessRecord {
    pub process_id: [u8; 16],
    pub invocation_id: [u8; 16],
    pub workspace_id: [u8; 16],
    pub task_run_id: [u8; 16],
    pub attempt_id: [u8; 16],
    pub principal_id: String,
    pub state: i64,
    pub version: u64,
    pub next_output_sequence: u64,
    pub request_digest: [u8; 32],
    pub intent_digest: [u8; 32],
    pub owner_id: [u8; 16],
    pub binding_attempt_id: [u8; 16],
    pub session_id: [u8; 16],
    pub generation_id: [u8; 16],
    pub tree_handle: [u8; 16],
    pub pid: u32,
    pub start_identity: [u8; 32],
    pub launch_nonce: [u8; 16],
}

/// One durable, already-sanitized process output chunk.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurableProcessOutput {
    pub process_id: [u8; 16],
    pub sequence: u64,
    pub stream: i64,
    pub text: String,
}

/// Closed process-store failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProcessStoreError {
    #[error("process store unavailable")]
    Unavailable,
    #[error("process store contains corrupt data")]
    CorruptData,
    #[error("process store conflict")]
    Conflict,
}

impl StoreTransaction {
    /// Upserts one owner-bound process record atomically.
    pub fn save_process_record(
        &self,
        record: &DurableProcessRecord,
    ) -> Result<(), ProcessStoreError> {
        let connection = self
            .inner
            .writer
            .lock()
            .map_err(|_| ProcessStoreError::Unavailable)?;
        connection
            .execute(
                "INSERT INTO process_registry
                 (process_id, invocation_id, workspace_id, task_run_id, attempt_id,
                  principal_id, state, version, next_output_sequence, request_digest,
                  intent_digest,
                  owner_id, binding_attempt_id, session_id, generation_id, tree_handle,
                  pid, start_identity, launch_nonce, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                         ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19,
                         COALESCE((SELECT created_at FROM process_registry WHERE process_id = ?1), ?20),
                         ?20)
                 ON CONFLICT(process_id) DO UPDATE SET
                   invocation_id = excluded.invocation_id,
                   workspace_id = excluded.workspace_id,
                   task_run_id = excluded.task_run_id,
                   attempt_id = excluded.attempt_id,
                   principal_id = excluded.principal_id,
                   state = excluded.state,
                   version = excluded.version,
                   next_output_sequence = excluded.next_output_sequence,
                   request_digest = excluded.request_digest,
                   intent_digest = excluded.intent_digest,
                   owner_id = excluded.owner_id,
                   binding_attempt_id = excluded.binding_attempt_id,
                   session_id = excluded.session_id,
                   generation_id = excluded.generation_id,
                   tree_handle = excluded.tree_handle,
                   pid = excluded.pid,
                   start_identity = excluded.start_identity,
                   launch_nonce = excluded.launch_nonce,
                   updated_at = excluded.updated_at
                 WHERE process_registry.invocation_id = excluded.invocation_id
                   AND process_registry.workspace_id = excluded.workspace_id
                   AND process_registry.task_run_id = excluded.task_run_id
                   AND process_registry.attempt_id = excluded.attempt_id
                   AND process_registry.principal_id = excluded.principal_id
                   AND process_registry.request_digest = excluded.request_digest
                   AND process_registry.intent_digest = excluded.intent_digest
                   AND process_registry.owner_id = excluded.owner_id
                   AND process_registry.binding_attempt_id = excluded.binding_attempt_id
                   AND process_registry.session_id = excluded.session_id
                   AND process_registry.generation_id = excluded.generation_id
                   AND process_registry.tree_handle = excluded.tree_handle
                   AND process_registry.pid = excluded.pid
                   AND process_registry.start_identity = excluded.start_identity
                   AND process_registry.launch_nonce = excluded.launch_nonce",
                params![
                    record.process_id.as_slice(),
                    record.invocation_id.as_slice(),
                    record.workspace_id.as_slice(),
                    record.task_run_id.as_slice(),
                    record.attempt_id.as_slice(),
                    record.principal_id,
                    record.state,
                    i64::try_from(record.version).map_err(|_| ProcessStoreError::CorruptData)?,
                    i64::try_from(record.next_output_sequence)
                        .map_err(|_| ProcessStoreError::CorruptData)?,
                    record.request_digest.as_slice(),
                    record.intent_digest.as_slice(),
                    record.owner_id.as_slice(),
                    record.binding_attempt_id.as_slice(),
                    record.session_id.as_slice(),
                    record.generation_id.as_slice(),
                    record.tree_handle.as_slice(),
                    i64::from(record.pid),
                    record.start_identity.as_slice(),
                    record.launch_nonce.as_slice(),
                    now_micros().max(1),
                ],
            )
            .map_err(map_sql_error)?;
        if connection.changes() != 1 {
            return Err(ProcessStoreError::Conflict);
        }
        Ok(())
    }

    /// Loads all records owned by one authenticated principal.
    pub fn load_process_records(
        &self,
        principal_id: &str,
    ) -> Result<Vec<DurableProcessRecord>, ProcessStoreError> {
        let connection = self
            .inner
            .reader
            .lock()
            .map_err(|_| ProcessStoreError::Unavailable)?;
        let mut statement = connection
            .prepare(
                "SELECT process_id, invocation_id, workspace_id, task_run_id, attempt_id,
                        principal_id, state, version, next_output_sequence, request_digest,
                        intent_digest,
                        owner_id, binding_attempt_id, session_id, generation_id, tree_handle,
                        pid, start_identity, launch_nonce
                 FROM process_registry WHERE principal_id = ?1 ORDER BY created_at, process_id",
            )
            .map_err(|_| ProcessStoreError::Unavailable)?;
        let rows = statement
            .query_map([principal_id], decode_record)
            .map_err(|_| ProcessStoreError::Unavailable)?;
        rows.map(|row| row.map_err(|_| ProcessStoreError::CorruptData))
            .collect()
    }

    /// Loads durable output after a cursor for one process.
    pub fn load_process_output(
        &self,
        process_id: [u8; 16],
        after_sequence: u64,
    ) -> Result<Vec<DurableProcessOutput>, ProcessStoreError> {
        let after = i64::try_from(after_sequence).map_err(|_| ProcessStoreError::CorruptData)?;
        let connection = self
            .inner
            .reader
            .lock()
            .map_err(|_| ProcessStoreError::Unavailable)?;
        let mut statement = connection
            .prepare(
                "SELECT process_id, sequence, stream, text FROM process_output
                 WHERE process_id = ?1 AND sequence > ?2 ORDER BY sequence",
            )
            .map_err(|_| ProcessStoreError::Unavailable)?;
        let rows = statement
            .query_map(params![process_id.as_slice(), after], |row| {
                Ok(DurableProcessOutput {
                    process_id: fixed_blob(row.get(0)?, 16)?,
                    sequence: positive_u64(row.get(1)?)?,
                    stream: row.get(2)?,
                    text: row.get(3)?,
                })
            })
            .map_err(|_| ProcessStoreError::Unavailable)?;
        rows.map(|row| row.map_err(|_| ProcessStoreError::CorruptData))
            .collect()
    }

    /// Appends one sanitized output chunk exactly once.
    pub fn append_process_output(
        &self,
        output: &DurableProcessOutput,
    ) -> Result<(), ProcessStoreError> {
        let connection = self
            .inner
            .writer
            .lock()
            .map_err(|_| ProcessStoreError::Unavailable)?;
        connection
            .execute(
                "INSERT INTO process_output (process_id, sequence, stream, text, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(process_id, sequence) DO UPDATE SET
                   stream = excluded.stream,
                   text = excluded.text
                 WHERE process_output.stream = excluded.stream
                   AND process_output.text = excluded.text",
                params![
                    output.process_id.as_slice(),
                    i64::try_from(output.sequence).map_err(|_| ProcessStoreError::CorruptData)?,
                    output.stream,
                    output.text,
                    now_micros().max(1),
                ],
            )
            .map_err(map_sql_error)?;
        if connection.changes() != 1 {
            return Err(ProcessStoreError::Conflict);
        }
        Ok(())
    }
}

fn decode_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<DurableProcessRecord> {
    Ok(DurableProcessRecord {
        process_id: fixed_blob(row.get(0)?, 16)?,
        invocation_id: fixed_blob(row.get(1)?, 16)?,
        workspace_id: fixed_blob(row.get(2)?, 16)?,
        task_run_id: fixed_blob(row.get(3)?, 16)?,
        attempt_id: fixed_blob(row.get(4)?, 16)?,
        principal_id: row.get(5)?,
        state: row.get(6)?,
        version: positive_u64(row.get(7)?)?,
        next_output_sequence: positive_u64(row.get(8)?)?,
        request_digest: fixed_blob(row.get(9)?, 32)?,
        intent_digest: fixed_blob(row.get(10)?, 32)?,
        owner_id: fixed_blob(row.get(11)?, 16)?,
        binding_attempt_id: fixed_blob(row.get(12)?, 16)?,
        session_id: fixed_blob(row.get(13)?, 16)?,
        generation_id: fixed_blob(row.get(14)?, 16)?,
        tree_handle: fixed_blob(row.get(15)?, 16)?,
        pid: positive_u32(row.get(16)?)?,
        start_identity: fixed_blob(row.get(17)?, 32)?,
        launch_nonce: fixed_blob(row.get(18)?, 16)?,
    })
}

fn fixed_blob<const N: usize>(value: Vec<u8>, _: usize) -> rusqlite::Result<[u8; N]> {
    value.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

fn positive_u64(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn positive_u32(value: i64) -> rusqlite::Result<u32> {
    u32::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn map_sql_error(error: rusqlite::Error) -> ProcessStoreError {
    match error {
        rusqlite::Error::SqliteFailure(_, _) => ProcessStoreError::Unavailable,
        _ => ProcessStoreError::CorruptData,
    }
}

#[cfg(test)]
mod tests {
    include!("process_tests.rs");
}
