#[path = "ledger/run.rs"]
mod run;

use std::fmt;
use std::fs::File;
#[cfg(test)]
use std::path::Path;

use runne_native_qualification::VerifiedQualificationFenceFacts;
#[cfg(unix)]
use runne_sqlite_native_identity::file_database_identity;
use runne_sqlite_native_identity::{
    DatabaseFileIdentity, opened_database_identity, path_database_identity,
};
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};

use crate::{CanonicalRunBinding, record::FaultRecord};

/// Durable replay ledger for already-authenticated qualification facts.
pub struct QualificationReplayLedger {
    connection: Connection,
    #[cfg(unix)]
    root: crate::path_guard::GuardedRoot,
    database_witness: File,
    database_identity: DatabaseFileIdentity,
    poisoned: bool,
}

impl QualificationReplayLedger {
    /// Opens the fixed root-owned production replay ledger.
    ///
    /// # Errors
    ///
    /// Fails closed when any path, ownership, `SQLite` identity, schema, or
    /// durability setting cannot be verified.
    #[cfg(unix)]
    pub fn open_production() -> Result<Self, QualificationReplayLedgerError> {
        let root = crate::path_guard::production_root()?;
        Self::open_guarded(root)
    }

    /// Production ledger storage is unavailable outside Unix descriptor guards.
    #[cfg(not(unix))]
    pub fn open_production() -> Result<Self, QualificationReplayLedgerError> {
        Err(QualificationReplayLedgerError)
    }

    /// Consumes one verified fault record and persists independent replay keys.
    ///
    /// This persists replay state only. It does not authenticate evidence or
    /// grant bootstrap authority.
    ///
    /// # Errors
    ///
    /// Rejects malformed facts, immutable-run rebinding, any replay key reuse,
    /// or an uncertain SQLite/path/durability state. An uncertain ledger stays
    /// unavailable until a fresh guarded open.
    #[allow(clippy::needless_pass_by_value)]
    pub fn consume_fault(
        &mut self,
        facts: VerifiedQualificationFenceFacts,
        binding: CanonicalRunBinding,
    ) -> Result<(), QualificationReplayLedgerError> {
        self.verify_healthy()?;
        let record = FaultRecord::from_facts(&facts, &binding)?;
        if self.consume_record(&record).is_err()
            || self.record_is_persisted(&record).is_err()
            || self.verify_healthy().is_err()
        {
            self.poisoned = true;
            return Err(QualificationReplayLedgerError);
        }
        Ok(())
    }

    #[cfg(all(test, unix))]
    pub(crate) fn open_for_test(
        root: &Path,
        uid: u32,
    ) -> Result<Self, QualificationReplayLedgerError> {
        Self::open_guarded(crate::path_guard::test_root(root, uid)?)
    }

    #[cfg(unix)]
    fn open_guarded(
        root: crate::path_guard::GuardedRoot,
    ) -> Result<Self, QualificationReplayLedgerError> {
        let database = root.open_database()?;
        let database_was_created = database.created;
        let witness = File::from(database.fd);
        let witness_identity =
            file_database_identity(&witness).map_err(|_| QualificationReplayLedgerError)?;
        let path = root.path.join(crate::path_guard::DATABASE_NAME);
        root.verify_database_path()?;
        let journal = root.open_existing_journal()?;
        let connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(|_| QualificationReplayLedgerError)?;
        connection
            .execute_batch("BEGIN IMMEDIATE; ROLLBACK")
            .map_err(|_| QualificationReplayLedgerError)?;
        root.verify_journal_recovered(journal)?;
        let expected = path_database_identity(&path).map_err(|_| QualificationReplayLedgerError)?;
        let opened =
            opened_database_identity(&connection).map_err(|_| QualificationReplayLedgerError)?;
        if root.verify_database_path().is_err()
            || path_database_identity(&path).ok() != Some(expected)
            || witness_identity != expected
            || opened != expected
        {
            return Err(QualificationReplayLedgerError);
        }
        crate::schema::configure_connection(&connection)?;
        crate::schema::initialize_schema(&connection, database_was_created)?;
        let mut ledger = Self {
            connection,
            root,
            database_witness: witness,
            database_identity: expected,
            poisoned: false,
        };
        ledger.verify_healthy()?;
        Ok(ledger)
    }

    fn consume_record(
        &mut self,
        record: &FaultRecord,
    ) -> Result<(), QualificationReplayLedgerError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| QualificationReplayLedgerError)?;
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
        for (domain, key) in [
            (1_i64, record.context_id),
            (2_i64, record.context_nonce),
            (3_i64, record.ticket_id),
            (4_i64, record.ticket_nonce),
        ] {
            transaction
                .execute(
                    "INSERT INTO replay_keys (domain, replay_key, source_revision, workflow_run_id, namespace_sha256) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![domain, key.as_slice(), record.source.as_slice(), record.run, record.namespace.as_slice()],
                )
                .map_err(|_| QualificationReplayLedgerError)?;
        }
        transaction
            .execute(
                "INSERT INTO fault_cases (context_id, context_nonce, ticket_id, ticket_nonce, fingerprint, source_revision, workflow_run_id, namespace_sha256) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![record.context_id.as_slice(), record.context_nonce.as_slice(), record.ticket_id.as_slice(), record.ticket_nonce.as_slice(), record.fingerprint.as_slice(), record.source.as_slice(), record.run, record.namespace.as_slice()],
            )
            .map_err(|_| QualificationReplayLedgerError)?;
        transaction
            .commit()
            .map_err(|_| QualificationReplayLedgerError)
    }

    fn record_is_persisted(
        &self,
        record: &FaultRecord,
    ) -> Result<(), QualificationReplayLedgerError> {
        let immutable: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM immutable_runs WHERE source_revision=?1 AND workflow_run_id=?2 AND namespace_sha256=?3 AND candidate_sha256=?4 AND raw_tuple_sha256=?5 AND manifest_sha256=?6 AND profile_sha256=?7",
            params![record.source.as_slice(), record.run, record.namespace.as_slice(), record.candidate.as_slice(), record.raw_tuple.as_slice(), record.manifest.as_slice(), record.profile.as_slice()],
            |row| row.get(0),
        ).map_err(|_| QualificationReplayLedgerError)?;
        let keys: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM replay_keys WHERE (domain=1 AND replay_key=?1 AND source_revision=?5 AND workflow_run_id=?6 AND namespace_sha256=?7) OR (domain=2 AND replay_key=?2 AND source_revision=?5 AND workflow_run_id=?6 AND namespace_sha256=?7) OR (domain=3 AND replay_key=?3 AND source_revision=?5 AND workflow_run_id=?6 AND namespace_sha256=?7) OR (domain=4 AND replay_key=?4 AND source_revision=?5 AND workflow_run_id=?6 AND namespace_sha256=?7)",
            params![record.context_id.as_slice(), record.context_nonce.as_slice(), record.ticket_id.as_slice(), record.ticket_nonce.as_slice(), record.source.as_slice(), record.run, record.namespace.as_slice()],
            |row| row.get(0),
        ).map_err(|_| QualificationReplayLedgerError)?;
        let fault: i64 = self.connection.query_row(
            "SELECT COUNT(*) FROM fault_cases WHERE context_id=?1 AND context_nonce=?2 AND ticket_id=?3 AND ticket_nonce=?4 AND fingerprint=?5 AND source_revision=?6 AND workflow_run_id=?7 AND namespace_sha256=?8",
            params![record.context_id.as_slice(), record.context_nonce.as_slice(), record.ticket_id.as_slice(), record.ticket_nonce.as_slice(), record.fingerprint.as_slice(), record.source.as_slice(), record.run, record.namespace.as_slice()],
            |row| row.get(0),
        ).map_err(|_| QualificationReplayLedgerError)?;
        (immutable == 1 && keys == 4 && fault == 1)
            .then_some(())
            .ok_or(QualificationReplayLedgerError)
    }

    fn verify_healthy(&mut self) -> Result<(), QualificationReplayLedgerError> {
        let sqlite_is_exact =
            matches!(crate::schema::pragmas_are_exact(&self.connection), Ok(true))
                && matches!(
                    crate::schema::integrity_is_exact(&self.connection),
                    Ok(true)
                );
        if self.poisoned || !sqlite_is_exact {
            self.poisoned = true;
            return Err(QualificationReplayLedgerError);
        }
        #[cfg(unix)]
        if self.root.verify_database_path().is_err()
            || self
                .root
                .verify_database_witness(&self.database_witness)
                .is_err()
            || path_database_identity(&self.root.path.join(crate::path_guard::DATABASE_NAME)).ok()
                != Some(self.database_identity)
            || file_database_identity(&self.database_witness).ok() != Some(self.database_identity)
            || opened_database_identity(&self.connection).ok() != Some(self.database_identity)
            || runne_sqlite_handle_identity::main_file_has_moved(&self.connection).ok()
                != Some(false)
            || !matches!(
                runne_sqlite_handle_identity::journal_file_has_moved(&self.connection),
                Ok(None | Some(false))
            )
        {
            self.poisoned = true;
            return Err(QualificationReplayLedgerError);
        }
        Ok(())
    }
}

/// Closed replay-persistence rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationReplayLedgerError;

impl fmt::Display for QualificationReplayLedgerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("qualification replay ledger rejected")
    }
}

impl std::error::Error for QualificationReplayLedgerError {}

#[cfg(test)]
#[path = "ledger/tests.rs"]
mod tests;
