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
mod corrupt_recovery;
use codec::*;

/// Managed SQLite persistence for opaque scanner checkpoint metadata.
#[derive(Clone)]
pub struct SqliteProviderRecoveryStore {
    connection: Arc<Mutex<ManagedConnection>>,
    canonical_path: PathBuf,
}

impl SqliteProviderRecoveryStore {
    /// Opens the scanner projection through the authoritative managed connection factory.
    pub fn open(
        path: &Path,
        authority_id: [u8; 16],
    ) -> Result<Self, ScannerRecoveryPersistenceError> {
        let mut recovery_name = path.as_os_str().to_owned();
        recovery_name.push(".scanner-recovery");
        let recovery_path = Path::new(&recovery_name);
        let connection = if recovery_path.exists() {
            schema::reopen_managed_scanner_sidecar(recovery_path, authority_id)
                .map_err(|_| ScannerRecoveryPersistenceError::Unavailable)?
        } else {
            let mut connection =
                schema::open_managed_connection(recovery_path, ConnectionMode::Writer)
                    .map_err(|_| ScannerRecoveryPersistenceError::Unavailable)?;
            initialize_sidecar(&mut connection, authority_id)?;
            connection
        };
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

fn initialize_sidecar(
    connection: &mut ManagedConnection,
    authority_id: [u8; 16],
) -> Result<(), ScannerRecoveryPersistenceError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sql)?;
    transaction
        .execute_batch(schema::SCANNER_IDENTITY_SQL)
        .map_err(map_sql)?;
    transaction
        .execute_batch(schema::SCANNER_RECOVERY_SQL)
        .map_err(map_sql)?;
    transaction
        .pragma_update(None, "user_version", 2_i64)
        .map_err(map_sql)?;
    transaction
        .execute(
            "INSERT INTO scanner_recovery_schema
             (id, schema_kind, schema_version, authority_id)
             VALUES (1, 'gocode.provider-scanner-recovery', 2, ?1)",
            [authority_id.as_slice()],
        )
        .map_err(map_sql)?;
    transaction.commit().map_err(map_sql)
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
                if !same_scanner_authority(head.binding, binding) || head.disposition.is_some() {
                    return Err(ScannerRecoveryPersistenceError::Conflict);
                }
                if head.sequence == Some(checkpoint.sequence())
                    && head.digest == Some(checkpoint.digest())
                {
                    if head.binding != binding {
                        return Err(ScannerRecoveryPersistenceError::Conflict);
                    }
                    update_checkpoint(&transaction, checkpoint)?;
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
        advance_durable(&self.connection, checkpoint, false)
    }

    fn advance_final_checkpoint(
        &self,
        checkpoint: ScannerCheckpoint,
    ) -> Result<(), ScannerRecoveryPersistenceError> {
        advance_durable(&self.connection, checkpoint, true)
    }

    fn commit_terminal(
        &self,
        binding: TailBinding,
        candidate: ScannerTerminalDisposition,
    ) -> Result<ScannerTerminalDisposition, ScannerRecoveryPersistenceError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ScannerRecoveryPersistenceError::Unavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        let current = current_head(&transaction, binding.attempt_id())?;
        let authoritative = match current {
            Some(head) => {
                if head.binding != binding {
                    return Err(ScannerRecoveryPersistenceError::Conflict);
                }
                let disposition = head
                    .disposition
                    .map_or(candidate, |value| value.dominant(candidate));
                if disposition == ScannerTerminalDisposition::Completed
                    && (head.digest.is_none()
                        || head.completion_digest != head.digest
                        || head.durable_digest != head.digest
                        || head.durable_cursor != binding.cursor()
                        || head.checkpoint_high_water != Some(head.durable_high_water))
                {
                    return Err(ScannerRecoveryPersistenceError::Conflict);
                }
                let changed = transaction
                    .execute(
                        "UPDATE provider_scanner_recovery SET disposition=?1 WHERE attempt_id=?2 AND fencing_token=?3 AND policy_epoch=?4 AND matcher_epoch=?5 AND algorithm_version=?6 AND COALESCE(checkpoint_cursor,0)=?7",
                        params![
                            encode_disposition(disposition),
                            binding.attempt_id().as_bytes(),
                            as_i64(head.binding.fencing_token())?,
                            as_i64(head.binding.policy_epoch())?,
                            as_i64(head.binding.matcher_epoch())?,
                            i64::from(head.binding.algorithm_version()),
                            as_i64(head.binding.cursor())?,
                        ],
                    )
                    .map_err(map_sql)?;
                if changed != 1 {
                    return Err(ScannerRecoveryPersistenceError::Conflict);
                }
                disposition
            }
            None => {
                if candidate == ScannerTerminalDisposition::Completed {
                    return Err(ScannerRecoveryPersistenceError::Conflict);
                }
                transaction.execute(
                    "INSERT INTO provider_scanner_recovery (attempt_id,fencing_token,policy_epoch,matcher_epoch,algorithm_version,disposition) VALUES (?1,?2,?3,?4,?5,?6)",
                    params![binding.attempt_id().as_bytes(), as_i64(binding.fencing_token())?, as_i64(binding.policy_epoch())?, as_i64(binding.matcher_epoch())?, i64::from(binding.algorithm_version()), encode_disposition(candidate)],
                ).map_err(map_sql)?;
                candidate
            }
        };
        transaction.commit().map_err(map_sql)?;
        Ok(authoritative)
    }

    fn terminalize_corrupt_checkpoint(
        &self,
        expected_binding: TailBinding,
    ) -> Result<ScannerTerminalDisposition, ScannerRecoveryPersistenceError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ScannerRecoveryPersistenceError::Unavailable)?;
        corrupt_recovery::terminalize(&mut connection, expected_binding)
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
            "SELECT fencing_token,policy_epoch,matcher_epoch,algorithm_version,tail_id,tail_version,binding_digest,checkpoint_sequence,checkpoint_cursor,checkpoint_safe_high_water,checkpoint_id,checkpoint_digest,durable_cursor,durable_safe_high_water,durable_checkpoint_digest,completion_checkpoint_digest,disposition FROM provider_scanner_recovery WHERE attempt_id=?1",
            [attempt_id.as_bytes()], |row| decode_record(attempt_id, row),
        ).optional().map_err(map_sql)?.transpose()
    }
}

fn same_scanner_authority(left: TailBinding, right: TailBinding) -> bool {
    left.attempt_id() == right.attempt_id()
        && left.fencing_token() == right.fencing_token()
        && left.policy_epoch() == right.policy_epoch()
        && left.matcher_epoch() == right.matcher_epoch()
        && left.algorithm_version() == right.algorithm_version()
}

fn advance_durable(
    connection: &Arc<Mutex<ManagedConnection>>,
    checkpoint: ScannerCheckpoint,
    final_checkpoint: bool,
) -> Result<(), ScannerRecoveryPersistenceError> {
    let binding = checkpoint.binding();
    let mut connection = connection
        .lock()
        .map_err(|_| ScannerRecoveryPersistenceError::Unavailable)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sql)?;
    let completion = final_checkpoint.then_some(checkpoint.digest());
    let changed = transaction.execute(
        "UPDATE provider_scanner_recovery SET durable_cursor=?1,durable_safe_high_water=?2,durable_checkpoint_digest=?3,completion_checkpoint_digest=?4 WHERE attempt_id=?5 AND fencing_token=?6 AND policy_epoch=?7 AND matcher_epoch=?8 AND algorithm_version=?9 AND checkpoint_cursor=?1 AND checkpoint_safe_high_water=?2 AND checkpoint_digest=?3 AND disposition IS NULL",
        params![as_i64(binding.cursor())?,as_i64(checkpoint.safe_prefix_high_water())?,checkpoint.digest(),completion,binding.attempt_id().as_bytes(),as_i64(binding.fencing_token())?,as_i64(binding.policy_epoch())?,as_i64(binding.matcher_epoch())?,i64::from(binding.algorithm_version())],
    ).map_err(map_sql)?;
    if changed != 1 {
        return Err(ScannerRecoveryPersistenceError::Conflict);
    }
    transaction.commit().map_err(map_sql)
}
