use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use gocode_provider::{
    DispatchAttemptId, ScannerCheckpoint, ScannerTerminalDisposition, TailBinding,
};
use gocode_runtime::provider_redaction::{
    ScannerRecoveryPersistence, ScannerRecoveryPersistenceError, ScannerRecoveryRecord,
};
use rusqlite::{OptionalExtension as _, TransactionBehavior, params};

use crate::schema::{self, ConnectionMode, ManagedConnection};

mod codec;
use codec::*;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS provider_scanner_recovery (
 attempt_id BLOB PRIMARY KEY CHECK(length(attempt_id) = 16),
 fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
 policy_epoch INTEGER NOT NULL CHECK(policy_epoch > 0),
 matcher_epoch INTEGER NOT NULL CHECK(matcher_epoch > 0),
 algorithm_version INTEGER NOT NULL CHECK(algorithm_version > 0),
 tail_id BLOB CHECK(tail_id IS NULL OR length(tail_id) = 16),
 tail_version INTEGER CHECK(tail_version IS NULL OR tail_version > 0),
 binding_digest BLOB CHECK(binding_digest IS NULL OR length(binding_digest) = 32),
 checkpoint_sequence INTEGER CHECK(checkpoint_sequence IS NULL OR checkpoint_sequence > 0),
 checkpoint_cursor INTEGER CHECK(checkpoint_cursor IS NULL OR checkpoint_cursor >= 0),
 checkpoint_safe_high_water INTEGER CHECK(checkpoint_safe_high_water IS NULL OR checkpoint_safe_high_water >= 0),
 checkpoint_id BLOB CHECK(checkpoint_id IS NULL OR length(checkpoint_id) = 16),
 checkpoint_digest BLOB CHECK(checkpoint_digest IS NULL OR length(checkpoint_digest) = 32),
 durable_cursor INTEGER NOT NULL DEFAULT 0 CHECK(durable_cursor >= 0),
 durable_safe_high_water INTEGER NOT NULL DEFAULT 0 CHECK(durable_safe_high_water >= 0),
 durable_checkpoint_digest BLOB CHECK(durable_checkpoint_digest IS NULL OR length(durable_checkpoint_digest) = 32),
 disposition INTEGER CHECK(disposition IS NULL OR disposition BETWEEN 1 AND 6),
 CHECK((tail_id IS NULL AND tail_version IS NULL AND binding_digest IS NULL AND checkpoint_sequence IS NULL AND checkpoint_cursor IS NULL AND checkpoint_safe_high_water IS NULL AND checkpoint_id IS NULL AND checkpoint_digest IS NULL)
    OR (tail_id IS NOT NULL AND tail_version IS NOT NULL AND binding_digest IS NOT NULL AND checkpoint_sequence IS NOT NULL AND checkpoint_cursor IS NOT NULL AND checkpoint_safe_high_water IS NOT NULL AND checkpoint_id IS NOT NULL AND checkpoint_digest IS NOT NULL))
);
"#;

/// Managed SQLite persistence for opaque scanner checkpoint metadata.
#[derive(Clone)]
pub struct SqliteProviderRecoveryStore {
    connection: Arc<Mutex<ManagedConnection>>,
    canonical_path: PathBuf,
}

impl SqliteProviderRecoveryStore {
    /// Opens the scanner projection through the authoritative managed connection factory.
    pub fn open(path: &Path) -> Result<Self, ScannerRecoveryPersistenceError> {
        let mut recovery_name = path.as_os_str().to_owned();
        recovery_name.push(".scanner-recovery");
        let connection =
            schema::open_managed_connection(Path::new(&recovery_name), ConnectionMode::Writer)
                .map_err(|_| ScannerRecoveryPersistenceError::Unavailable)?;
        connection
            .execute_batch(SCHEMA)
            .map_err(|_| ScannerRecoveryPersistenceError::Unavailable)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
            canonical_path: path.to_path_buf(),
        })
    }

    /// Counts authoritative event replay and provider terminal outbox rows.
    pub fn canonical_publication_counts(
        &self,
    ) -> Result<(u64, u64), ScannerRecoveryPersistenceError> {
        let connection =
            schema::open_managed_connection(&self.canonical_path, ConnectionMode::Reader)
                .map_err(|_| ScannerRecoveryPersistenceError::Unavailable)?;
        let replay = table_count(&connection, "events")?;
        let outbox = table_count(&connection, "provider_terminal_outbox")?;
        Ok((replay, outbox))
    }
}

impl ScannerRecoveryPersistence for SqliteProviderRecoveryStore {
    fn persist_checkpoint(
        &self,
        checkpoint: ScannerCheckpoint,
    ) -> Result<(), ScannerRecoveryPersistenceError> {
        let binding = checkpoint.binding();
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ScannerRecoveryPersistenceError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        let current = current_head(&transaction, binding.attempt_id())?;
        match current {
            None => insert_checkpoint(&transaction, checkpoint)?,
            Some(head) => {
                if head.fence != binding.fencing_token() || head.disposition.is_some() {
                    return Err(ScannerRecoveryPersistenceError::Conflict);
                }
                if head.sequence == Some(checkpoint.sequence())
                    && head.digest == Some(checkpoint.digest())
                {
                    transaction.commit().map_err(map_sql)?;
                    return Ok(());
                }
                if head.sequence.and_then(|value| value.checked_add(1))
                    != Some(checkpoint.sequence())
                {
                    return Err(ScannerRecoveryPersistenceError::Conflict);
                }
                update_checkpoint(&transaction, checkpoint)?;
            }
        }
        transaction.commit().map_err(map_sql)
    }

    fn advance_checkpoint(
        &self,
        checkpoint: ScannerCheckpoint,
    ) -> Result<(), ScannerRecoveryPersistenceError> {
        let binding = checkpoint.binding();
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ScannerRecoveryPersistenceError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        let changed = transaction.execute(
            "UPDATE provider_scanner_recovery SET durable_cursor=?1, durable_safe_high_water=?2, durable_checkpoint_digest=?3
             WHERE attempt_id=?4 AND fencing_token=?5 AND checkpoint_digest=?3 AND disposition IS NULL",
            params![as_i64(binding.cursor())?, as_i64(checkpoint.safe_prefix_high_water())?, checkpoint.digest(), binding.attempt_id().as_bytes(), as_i64(binding.fencing_token())?],
        ).map_err(map_sql)?;
        if changed != 1 {
            return Err(ScannerRecoveryPersistenceError::Conflict);
        }
        transaction.commit().map_err(map_sql)
    }

    fn commit_terminal(
        &self,
        binding: TailBinding,
        candidate: ScannerTerminalDisposition,
    ) -> Result<(), ScannerRecoveryPersistenceError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ScannerRecoveryPersistenceError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        let current = current_head(&transaction, binding.attempt_id())?;
        match current {
            Some(head) => {
                if head.fence != binding.fencing_token() {
                    return Err(ScannerRecoveryPersistenceError::Conflict);
                }
                let disposition = head
                    .disposition
                    .map_or(candidate, |value| value.dominant(candidate));
                if disposition == ScannerTerminalDisposition::Completed
                    && (head.digest.is_none() || head.durable_digest != head.digest)
                {
                    return Err(ScannerRecoveryPersistenceError::Conflict);
                }
                transaction
                    .execute(
                        "UPDATE provider_scanner_recovery SET disposition=?1 WHERE attempt_id=?2",
                        params![
                            encode_disposition(disposition),
                            binding.attempt_id().as_bytes()
                        ],
                    )
                    .map_err(map_sql)?;
            }
            None => {
                if candidate == ScannerTerminalDisposition::Completed {
                    return Err(ScannerRecoveryPersistenceError::Conflict);
                }
                transaction.execute(
                    "INSERT INTO provider_scanner_recovery (attempt_id,fencing_token,policy_epoch,matcher_epoch,algorithm_version,disposition) VALUES (?1,?2,?3,?4,?5,?6)",
                    params![binding.attempt_id().as_bytes(), as_i64(binding.fencing_token())?, as_i64(binding.policy_epoch())?, as_i64(binding.matcher_epoch())?, i64::from(binding.algorithm_version()), encode_disposition(candidate)],
                ).map_err(map_sql)?;
            }
        }
        transaction.commit().map_err(map_sql)
    }

    fn load(
        &self,
        attempt_id: DispatchAttemptId,
    ) -> Result<Option<ScannerRecoveryRecord>, ScannerRecoveryPersistenceError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ScannerRecoveryPersistenceError::Unavailable)?;
        connection.query_row(
            "SELECT fencing_token,policy_epoch,matcher_epoch,algorithm_version,tail_id,tail_version,binding_digest,checkpoint_sequence,checkpoint_cursor,checkpoint_safe_high_water,checkpoint_id,checkpoint_digest,durable_cursor,durable_safe_high_water,durable_checkpoint_digest,disposition FROM provider_scanner_recovery WHERE attempt_id=?1",
            [attempt_id.as_bytes()], |row| decode_record(attempt_id, row),
        ).optional().map_err(map_sql)?.transpose()
    }
}
