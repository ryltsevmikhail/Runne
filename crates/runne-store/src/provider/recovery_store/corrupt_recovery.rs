use runne_provider::{ScannerTerminalDisposition, TailBinding};
use runne_runtime::provider_redaction::ScannerRecoveryPersistenceError;
use rusqlite::{OptionalExtension as _, TransactionBehavior, params};

use super::{as_i64, decode_optional_disposition, decode_record, map_sql};
use crate::schema::ManagedConnection;

const RECORD_FIELDS: &str = "fencing_token,policy_epoch,matcher_epoch,algorithm_version,tail_id,tail_version,\
     binding_digest,checkpoint_sequence,checkpoint_cursor,checkpoint_safe_high_water,\
     checkpoint_id,checkpoint_digest,durable_cursor,durable_safe_high_water,\
     durable_checkpoint_digest,completion_checkpoint_digest,disposition";

pub(super) fn terminalize(
    connection: &mut ManagedConnection,
    expected: TailBinding,
) -> Result<ScannerTerminalDisposition, ScannerRecoveryPersistenceError> {
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sql)?;
    let sql = format!(
        "SELECT {RECORD_FIELDS} FROM provider_scanner_recovery \
         WHERE attempt_id=?1 AND fencing_token=?2 AND policy_epoch=?3 \
         AND matcher_epoch=?4 AND algorithm_version=?5"
    );
    let decoded = transaction
        .query_row(
            &sql,
            params![
                expected.attempt_id().as_bytes(),
                as_i64(expected.fencing_token())?,
                as_i64(expected.policy_epoch())?,
                as_i64(expected.matcher_epoch())?,
                i64::from(expected.algorithm_version()),
            ],
            |row| decode_record(expected.attempt_id(), row),
        )
        .optional();
    match decoded {
        Ok(Some(Err(ScannerRecoveryPersistenceError::Corrupt)))
        | Err(rusqlite::Error::InvalidQuery) => {}
        Ok(Some(Ok(_))) | Ok(Some(Err(_))) | Ok(None) => {
            return Err(ScannerRecoveryPersistenceError::Conflict);
        }
        Err(error) => return Err(map_sql(error)),
    }
    let changed = transaction
        .execute(
            "UPDATE provider_scanner_recovery
             SET disposition=CASE WHEN disposition IN (1,2,3) THEN disposition ELSE 4 END
             WHERE attempt_id=?1 AND fencing_token=?2 AND policy_epoch=?3
             AND matcher_epoch=?4 AND algorithm_version=?5",
            params![
                expected.attempt_id().as_bytes(),
                as_i64(expected.fencing_token())?,
                as_i64(expected.policy_epoch())?,
                as_i64(expected.matcher_epoch())?,
                i64::from(expected.algorithm_version()),
            ],
        )
        .map_err(map_sql)?;
    if changed != 1 {
        return Err(ScannerRecoveryPersistenceError::Conflict);
    }
    let code = transaction
        .query_row(
            "SELECT disposition FROM provider_scanner_recovery WHERE attempt_id=?1",
            [expected.attempt_id().as_bytes()],
            |row| row.get(0),
        )
        .map_err(map_sql)?;
    let authoritative = decode_optional_disposition(Some(code))
        .map_err(map_sql)?
        .ok_or(ScannerRecoveryPersistenceError::Corrupt)?;
    transaction.commit().map_err(map_sql)?;
    Ok(authoritative)
}
