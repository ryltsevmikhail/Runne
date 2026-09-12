use rusqlite::{Connection, params};

use crate::{QualificationReplayLedgerError, run_record::RunRecord};

pub fn reject_reserved_fault(
    connection: &Connection,
    context_id: [u8; 32],
    nonce: [u8; 32],
) -> Result<(), QualificationReplayLedgerError> {
    let reserved: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM bootstrap_arms WHERE context_id=?1 OR context_nonce=?2)",
            params![context_id.as_slice(), nonce.as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| QualificationReplayLedgerError)?;
    (!reserved)
        .then_some(())
        .ok_or(QualificationReplayLedgerError)
}

pub fn check_reserved_run(
    connection: &Connection,
    record: &RunRecord,
) -> Result<(), QualificationReplayLedgerError> {
    let conflicting: i64 = connection.query_row(
        "SELECT COUNT(*) FROM bootstrap_arms WHERE context_id=?1 OR context_nonce=?2 OR (source_revision=?3 AND workflow_run_id=?4 AND namespace_sha256=?5)",
        params![record.context_id.as_slice(), record.context_nonce.as_slice(), record.source.as_slice(), record.run, record.namespace.as_slice()],
        |row| row.get(0),
    ).map_err(|_| QualificationReplayLedgerError)?;
    if conflicting == 0 {
        return Ok(());
    }
    let exact: i64 = connection.query_row(
        "SELECT COUNT(*) FROM bootstrap_arms WHERE state=3 AND context_id=?1 AND context_nonce=?2 AND source_revision=?3 AND workflow_run_id=?4 AND namespace_sha256=?5 AND candidate_sha256=?6 AND raw_tuple_sha256=?7 AND manifest_sha256=?8 AND profile_sha256=?9 AND daemon_challenge=?10 AND issued_at=?11 AND expires_at=?12 AND run_not_after=?13",
        params![record.context_id.as_slice(), record.context_nonce.as_slice(), record.source.as_slice(), record.run, record.namespace.as_slice(), record.candidate.as_slice(), record.raw_tuple.as_slice(), record.manifest.as_slice(), record.profile.as_slice(), record.challenge.as_slice(), record.issued_at, record.expires_at, record.run_not_after],
        |row| row.get(0),
    ).map_err(|_| QualificationReplayLedgerError)?;
    (conflicting == 1 && exact == 1)
        .then_some(())
        .ok_or(QualificationReplayLedgerError)
}
