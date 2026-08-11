use gocode_provider::{
    DispatchAttemptId, NativeSecretRef, ScannerCheckpoint, ScannerTerminalDisposition,
    ScannerUncertainReason, TailBinding,
};
use gocode_runtime::provider_redaction::{ScannerRecoveryPersistenceError, ScannerRecoveryRecord};
use rusqlite::{OptionalExtension as _, params};

use crate::schema::ManagedConnection;

#[derive(Clone, Copy)]
pub(super) struct Head {
    pub(super) binding: TailBinding,
    pub(super) sequence: Option<u64>,
    pub(super) checkpoint_high_water: Option<u64>,
    pub(super) digest: Option<[u8; 32]>,
    pub(super) durable_cursor: u64,
    pub(super) durable_high_water: u64,
    pub(super) durable_digest: Option<[u8; 32]>,
    pub(super) completion_digest: Option<[u8; 32]>,
    pub(super) disposition: Option<ScannerTerminalDisposition>,
}

pub(super) fn current_head(
    transaction: &rusqlite::Transaction<'_>,
    attempt: DispatchAttemptId,
) -> Result<Option<Head>, ScannerRecoveryPersistenceError> {
    transaction.query_row(
        "SELECT fencing_token,policy_epoch,matcher_epoch,algorithm_version,checkpoint_cursor,checkpoint_sequence,checkpoint_safe_high_water,checkpoint_digest,durable_cursor,durable_safe_high_water,durable_checkpoint_digest,completion_checkpoint_digest,disposition FROM provider_scanner_recovery WHERE attempt_id=?1",
        [attempt.as_bytes()], |row| {
            let binding = TailBinding::new(attempt, as_u64(row.get(0)?)?, as_u64(row.get(1)?)?, as_u64(row.get(2)?)?, u32::try_from(row.get::<_, i64>(3)?).map_err(|_| rusqlite::Error::InvalidQuery)?, optional_u64(row.get(4)?)?.unwrap_or(0)).map_err(|_| rusqlite::Error::InvalidQuery)?;
            Ok(Head { binding, sequence: optional_u64(row.get(5)?)?, checkpoint_high_water: optional_u64(row.get(6)?)?, digest: optional_fixed(row.get(7)?)?, durable_cursor: as_u64(row.get(8)?)?, durable_high_water: as_u64(row.get(9)?)?, durable_digest: optional_fixed(row.get(10)?)?, completion_digest: optional_fixed(row.get(11)?)?, disposition: decode_optional_disposition(row.get(12)?)? })
        },
    ).optional().map_err(map_sql)
}

pub(super) fn insert_checkpoint(
    transaction: &rusqlite::Transaction<'_>,
    checkpoint: ScannerCheckpoint,
) -> Result<(), ScannerRecoveryPersistenceError> {
    let binding = checkpoint.binding();
    let reference = checkpoint.tail_reference();
    transaction.execute(
        "INSERT INTO provider_scanner_recovery (attempt_id,fencing_token,policy_epoch,matcher_epoch,algorithm_version,tail_id,tail_version,binding_digest,checkpoint_sequence,checkpoint_cursor,checkpoint_safe_high_water,checkpoint_id,checkpoint_digest) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        params![binding.attempt_id().as_bytes(),as_i64(binding.fencing_token())?,as_i64(binding.policy_epoch())?,as_i64(binding.matcher_epoch())?,i64::from(binding.algorithm_version()),reference.id(),i64::from(reference.version()),reference.binding_digest(),as_i64(checkpoint.sequence())?,as_i64(binding.cursor())?,as_i64(checkpoint.safe_prefix_high_water())?,checkpoint.checkpoint_id(),checkpoint.digest()],
    ).map_err(map_sql)?;
    Ok(())
}

pub(super) fn update_checkpoint(
    transaction: &rusqlite::Transaction<'_>,
    checkpoint: ScannerCheckpoint,
) -> Result<(), ScannerRecoveryPersistenceError> {
    let binding = checkpoint.binding();
    let reference = checkpoint.tail_reference();
    let changed = transaction.execute(
        "UPDATE provider_scanner_recovery SET tail_id=?1,tail_version=?2,binding_digest=?3,checkpoint_sequence=?4,checkpoint_cursor=?5,checkpoint_safe_high_water=?6,checkpoint_id=?7,checkpoint_digest=?8,completion_checkpoint_digest=NULL WHERE attempt_id=?9 AND fencing_token=?10 AND policy_epoch=?11 AND matcher_epoch=?12 AND algorithm_version=?13 AND disposition IS NULL",
        params![reference.id(),i64::from(reference.version()),reference.binding_digest(),as_i64(checkpoint.sequence())?,as_i64(binding.cursor())?,as_i64(checkpoint.safe_prefix_high_water())?,checkpoint.checkpoint_id(),checkpoint.digest(),binding.attempt_id().as_bytes(),as_i64(binding.fencing_token())?,as_i64(binding.policy_epoch())?,as_i64(binding.matcher_epoch())?,i64::from(binding.algorithm_version())],
    ).map_err(map_sql)?;
    if changed == 1 {
        Ok(())
    } else {
        Err(ScannerRecoveryPersistenceError::Conflict)
    }
}

pub(super) fn decode_record(
    attempt: DispatchAttemptId,
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Result<ScannerRecoveryRecord, ScannerRecoveryPersistenceError>> {
    let binding = TailBinding::new(
        attempt,
        as_u64(row.get(0)?)?,
        as_u64(row.get(1)?)?,
        as_u64(row.get(2)?)?,
        u32::try_from(row.get::<_, i64>(3)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
        optional_u64(row.get(8)?)?.unwrap_or(0),
    )
    .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let fields = (
        row.get::<_, Option<Vec<u8>>>(4)?,
        row.get::<_, Option<i64>>(5)?,
        row.get::<_, Option<Vec<u8>>>(6)?,
        row.get::<_, Option<i64>>(7)?,
        row.get::<_, Option<i64>>(9)?,
        row.get::<_, Option<Vec<u8>>>(10)?,
        row.get::<_, Option<Vec<u8>>>(11)?,
    );
    let checkpoint = match fields {
        (None, None, None, None, None, None, None) => None,
        (
            Some(id),
            Some(version),
            Some(binding_digest),
            Some(sequence),
            Some(high),
            Some(checkpoint_id),
            Some(digest),
        ) => {
            let reference = NativeSecretRef::new(
                fixed(id)?,
                u32::try_from(version).map_err(|_| rusqlite::Error::InvalidQuery)?,
                fixed(binding_digest)?,
            )
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
            Some(
                ScannerCheckpoint::from_durable(
                    reference,
                    binding,
                    as_u64(sequence)?,
                    as_u64(high)?,
                    fixed(checkpoint_id)?,
                    fixed(digest)?,
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            )
        }
        _ => return Ok(Err(ScannerRecoveryPersistenceError::Corrupt)),
    };
    let durable_cursor = as_u64(row.get(12)?)?;
    let durable_high_water = as_u64(row.get(13)?)?;
    let durable_digest = optional_fixed(row.get(14)?)?;
    let completion_digest = optional_fixed(row.get(15)?)?;
    let disposition = decode_optional_disposition(row.get(16)?)?;
    let completion_valid = completion_digest.is_none()
        || (checkpoint.is_some()
            && completion_digest == durable_digest
            && completion_digest == checkpoint.map(|value| value.digest())
            && durable_cursor == binding.cursor()
            && durable_high_water == checkpoint.map_or(0, |value| value.safe_prefix_high_water()));
    if !completion_valid
        || (disposition == Some(ScannerTerminalDisposition::Completed)
            && completion_digest.is_none())
    {
        return Ok(Err(ScannerRecoveryPersistenceError::Corrupt));
    }
    Ok(Ok(ScannerRecoveryRecord::new(
        binding,
        checkpoint,
        durable_cursor,
        durable_high_water,
        durable_digest,
        completion_digest,
        disposition,
    )))
}

pub(super) fn encode_disposition(value: ScannerTerminalDisposition) -> i64 {
    match value {
        ScannerTerminalDisposition::Uncertain(ScannerUncertainReason::SecretDetected) => 1,
        ScannerTerminalDisposition::Uncertain(
            ScannerUncertainReason::CredentialMatcherUnavailable,
        ) => 2,
        ScannerTerminalDisposition::Uncertain(
            ScannerUncertainReason::RedactionScannerUnavailable,
        ) => 3,
        ScannerTerminalDisposition::Uncertain(
            ScannerUncertainReason::CheckpointSecretStateUnavailable,
        ) => 4,
        ScannerTerminalDisposition::OutputLimitExceeded => 5,
        ScannerTerminalDisposition::Completed => 6,
    }
}
pub(super) fn decode_optional_disposition(
    value: Option<i64>,
) -> rusqlite::Result<Option<ScannerTerminalDisposition>> {
    value
        .map(|code| match code {
            1 => Ok(ScannerTerminalDisposition::Uncertain(
                ScannerUncertainReason::SecretDetected,
            )),
            2 => Ok(ScannerTerminalDisposition::Uncertain(
                ScannerUncertainReason::CredentialMatcherUnavailable,
            )),
            3 => Ok(ScannerTerminalDisposition::Uncertain(
                ScannerUncertainReason::RedactionScannerUnavailable,
            )),
            4 => Ok(ScannerTerminalDisposition::Uncertain(
                ScannerUncertainReason::CheckpointSecretStateUnavailable,
            )),
            5 => Ok(ScannerTerminalDisposition::OutputLimitExceeded),
            6 => Ok(ScannerTerminalDisposition::Completed),
            _ => Err(rusqlite::Error::InvalidQuery),
        })
        .transpose()
}
pub(super) fn table_count(
    connection: &ManagedConnection,
    table: &str,
) -> Result<u64, ScannerRecoveryPersistenceError> {
    let sql = format!("SELECT COUNT(*) FROM {table}");
    connection
        .query_row(&sql, [], |row| as_u64(row.get(0)?))
        .map_err(map_sql)
}
fn fixed<const N: usize>(bytes: Vec<u8>) -> rusqlite::Result<[u8; N]> {
    bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}
fn optional_fixed<const N: usize>(value: Option<Vec<u8>>) -> rusqlite::Result<Option<[u8; N]>> {
    value.map(fixed).transpose()
}
fn optional_u64(value: Option<i64>) -> rusqlite::Result<Option<u64>> {
    value.map(as_u64).transpose()
}
pub(super) fn as_i64(value: u64) -> Result<i64, ScannerRecoveryPersistenceError> {
    i64::try_from(value).map_err(|_| ScannerRecoveryPersistenceError::Corrupt)
}
fn as_u64(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery)
}
pub(super) fn map_sql(error: rusqlite::Error) -> ScannerRecoveryPersistenceError {
    if matches!(error, rusqlite::Error::InvalidQuery) {
        ScannerRecoveryPersistenceError::Corrupt
    } else {
        ScannerRecoveryPersistenceError::Unavailable
    }
}
