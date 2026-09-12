use runne_native_qualification::VerifiedQualificationRunBootstrapProof;
use rusqlite::{TransactionBehavior, params};

use super::{QualificationReplayLedger, QualificationReplayLedgerError};
use crate::run_record::RunRecord;

impl QualificationReplayLedger {
    /// Durably consumes one signed run-bootstrap proof after independent verification.
    ///
    /// Persistence success does not grant a session or any enrollment authority.
    /// Freshness is checked again against the system clock before persistence.
    ///
    /// # Errors
    /// Rejects any reused context ID/nonce, second bootstrap for the same run,
    /// immutable binding mismatch, or uncertain storage state.
    #[allow(clippy::needless_pass_by_value)]
    pub fn consume_run(
        &mut self,
        proof: VerifiedQualificationRunBootstrapProof,
    ) -> Result<(), QualificationReplayLedgerError> {
        self.consume_run_with_clock(proof, system_now)
    }

    #[cfg(test)]
    pub(super) fn consume_run_at(
        &mut self,
        proof: VerifiedQualificationRunBootstrapProof,
        now: u64,
    ) -> Result<(), QualificationReplayLedgerError> {
        self.consume_run_with_clock(proof, || Ok(now))
    }

    #[allow(clippy::needless_pass_by_value)]
    fn consume_run_with_clock(
        &mut self,
        proof: VerifiedQualificationRunBootstrapProof,
        clock: impl FnOnce() -> Result<u64, QualificationReplayLedgerError>,
    ) -> Result<(), QualificationReplayLedgerError> {
        self.verify_healthy()?;
        let record = RunRecord::from_facts(&proof)?;
        if self.consume_run_record_with_clock(&record, clock).is_err()
            || self.run_record_is_persisted(&record).is_err()
            || self.verify_healthy().is_err()
        {
            self.poisoned = true;
            return Err(QualificationReplayLedgerError);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn consume_run_record(
        &mut self,
        record: &RunRecord,
    ) -> Result<(), QualificationReplayLedgerError> {
        self.consume_run_record_with_clock(record, system_now)
    }

    fn consume_run_record_with_clock(
        &mut self,
        record: &RunRecord,
        clock: impl FnOnce() -> Result<u64, QualificationReplayLedgerError>,
    ) -> Result<(), QualificationReplayLedgerError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| QualificationReplayLedgerError)?;
        let now = clock()?;
        if now < record.issued_at || now >= record.expires_at || now >= record.run_not_after {
            return Err(QualificationReplayLedgerError);
        }
        transaction
            .execute(
                "INSERT INTO immutable_runs (source_revision, workflow_run_id, namespace_sha256, candidate_sha256, raw_tuple_sha256, manifest_sha256, profile_sha256) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT(source_revision, workflow_run_id, namespace_sha256) DO NOTHING",
                params![record.source.as_slice(), record.run, record.namespace.as_slice(), record.candidate.as_slice(), record.raw_tuple.as_slice(), record.manifest.as_slice(), record.profile.as_slice()],
            )
            .map_err(|_| QualificationReplayLedgerError)?;
        let existing: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = transaction
            .query_row(
                "SELECT candidate_sha256, raw_tuple_sha256, manifest_sha256, profile_sha256 FROM immutable_runs WHERE source_revision=?1 AND workflow_run_id=?2 AND namespace_sha256=?3",
                params![record.source.as_slice(), record.run, record.namespace.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .map_err(|_| QualificationReplayLedgerError)?;
        if existing
            != (
                record.candidate.to_vec(),
                record.raw_tuple.to_vec(),
                record.manifest.to_vec(),
                record.profile.to_vec(),
            )
        {
            return Err(QualificationReplayLedgerError);
        }
        super::bootstrap_reservations::check_reserved_run(&transaction, record)?;
        for (domain, key) in [(1_i64, record.context_id), (2_i64, record.context_nonce)] {
            transaction
                .execute(
                    "INSERT INTO replay_keys (domain, replay_key, source_revision, workflow_run_id, namespace_sha256) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![domain, key.as_slice(), record.source.as_slice(), record.run, record.namespace.as_slice()],
                )
                .map_err(|_| QualificationReplayLedgerError)?;
        }
        transaction
            .execute(
                "INSERT INTO run_bootstraps (context_id, context_nonce, fingerprint, source_revision, workflow_run_id, namespace_sha256, run_not_after, challenge) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![record.context_id.as_slice(), record.context_nonce.as_slice(), record.fingerprint.as_slice(), record.source.as_slice(), record.run, record.namespace.as_slice(), record.run_not_after, record.challenge.as_slice()],
            )
            .map_err(|_| QualificationReplayLedgerError)?;
        transaction
            .commit()
            .map_err(|_| QualificationReplayLedgerError)
    }

    fn run_record_is_persisted(
        &self,
        record: &RunRecord,
    ) -> Result<(), QualificationReplayLedgerError> {
        let immutable: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM immutable_runs WHERE source_revision=?1 AND workflow_run_id=?2 AND namespace_sha256=?3 AND candidate_sha256=?4 AND raw_tuple_sha256=?5 AND manifest_sha256=?6 AND profile_sha256=?7",
            params![record.source.as_slice(), record.run, record.namespace.as_slice(), record.candidate.as_slice(), record.raw_tuple.as_slice(), record.manifest.as_slice(), record.profile.as_slice()],
            |row| row.get(0),
        ).map_err(|_| QualificationReplayLedgerError)?;
        let keys: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM replay_keys WHERE source_revision=?3 AND workflow_run_id=?4 AND namespace_sha256=?5 AND ((domain=1 AND replay_key=?1) OR (domain=2 AND replay_key=?2))",
            params![record.context_id.as_slice(), record.context_nonce.as_slice(), record.source.as_slice(), record.run, record.namespace.as_slice()],
            |row| row.get(0),
        ).map_err(|_| QualificationReplayLedgerError)?;
        let fault: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM run_bootstraps WHERE context_id=?1 AND context_nonce=?2 AND fingerprint=?3 AND source_revision=?4 AND workflow_run_id=?5 AND namespace_sha256=?6 AND run_not_after=?7 AND challenge=?8",
            params![record.context_id.as_slice(), record.context_nonce.as_slice(), record.fingerprint.as_slice(), record.source.as_slice(), record.run, record.namespace.as_slice(), record.run_not_after, record.challenge.as_slice()],
            |row| row.get(0),
        ).map_err(|_| QualificationReplayLedgerError)?;
        (immutable == 1 && keys == 2 && fault == 1)
            .then_some(())
            .ok_or(QualificationReplayLedgerError)
    }
}

fn system_now() -> Result<u64, QualificationReplayLedgerError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| QualificationReplayLedgerError)
}
