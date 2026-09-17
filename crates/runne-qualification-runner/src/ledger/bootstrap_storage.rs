use runne_api::RunBinding;
use rusqlite::{Transaction, params};

use crate::{BootstrapPreparation, QualificationReplayLedgerError};

pub(super) fn reject_existing_bootstrap_replay(
    transaction: &Transaction<'_>,
    preparation: &BootstrapPreparation,
) -> Result<(), QualificationReplayLedgerError> {
    let binding = preparation.binding();
    let exists: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM bootstrap_arms WHERE offer_id=?1 OR context_id=?2 OR context_nonce=?3 OR (source_revision=?4 AND workflow_run_id=?5 AND namespace_sha256=?6)) OR EXISTS(SELECT 1 FROM run_bootstraps WHERE context_id=?2 OR context_nonce=?3 OR (source_revision=?4 AND workflow_run_id=?5 AND namespace_sha256=?6)) OR EXISTS(SELECT 1 FROM fault_cases WHERE context_id=?2 OR context_nonce=?3) OR EXISTS(SELECT 1 FROM replay_keys WHERE (domain=1 AND replay_key=?2) OR (domain=2 AND replay_key=?3))",
        params![preparation.offer_id().as_slice(), preparation.context_id().as_slice(), preparation.nonce().as_slice(), binding.source_revision().as_slice(), binding.workflow_run_id(), binding.namespace_sha256().as_slice()],
        |row| row.get(0),
    ).map_err(|_| QualificationReplayLedgerError)?;
    (exists == 0)
        .then_some(())
        .ok_or(QualificationReplayLedgerError)
}

pub(super) fn insert_immutable_run(
    transaction: &Transaction<'_>,
    binding: &RunBinding,
) -> Result<(), QualificationReplayLedgerError> {
    transaction
        .execute(
            "INSERT INTO immutable_runs (source_revision, workflow_run_id, namespace_sha256, candidate_sha256, raw_tuple_sha256, manifest_sha256, profile_sha256) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT(source_revision, workflow_run_id, namespace_sha256) DO NOTHING",
            params![binding.source_revision().as_slice(), binding.workflow_run_id(), binding.namespace_sha256().as_slice(), binding.candidate_sha256().as_slice(), binding.raw_v3_tuple_sha256().as_slice(), binding.manifest_sha256().as_slice(), binding.profile_sha256().as_slice()],
        )
        .map_err(|_| QualificationReplayLedgerError)?;
    let existing: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = transaction
        .query_row(
            "SELECT candidate_sha256, raw_tuple_sha256, manifest_sha256, profile_sha256 FROM immutable_runs WHERE source_revision=?1 AND workflow_run_id=?2 AND namespace_sha256=?3",
            params![binding.source_revision().as_slice(), binding.workflow_run_id(), binding.namespace_sha256().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(|_| QualificationReplayLedgerError)?;
    (existing
        == (
            binding.candidate_sha256().to_vec(),
            binding.raw_v3_tuple_sha256().to_vec(),
            binding.manifest_sha256().to_vec(),
            binding.profile_sha256().to_vec(),
        ))
        .then_some(())
        .ok_or(QualificationReplayLedgerError)
}
