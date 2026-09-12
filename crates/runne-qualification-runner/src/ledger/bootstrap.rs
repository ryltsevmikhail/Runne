use rusqlite::{TransactionBehavior, params};

use super::{QualificationReplayLedger, QualificationReplayLedgerError};
use crate::{BootstrapArmed, BootstrapPreparation};

#[path = "bootstrap_decode.rs"]
mod decode;
#[path = "bootstrap_storage.rs"]
mod storage;

use decode::{armed_from_stored, is_current, is_current_armed, stored_armed, system_now};
use storage::{insert_immutable_run, reject_existing_bootstrap_replay};

const PREPARED: i64 = 1;
const ARMED: i64 = 2;
const ISSUED: i64 = 3;
const CONSUMED: i64 = 4;

impl QualificationReplayLedger {
    /// # Errors
    ///
    /// Returns an error when the preparation is stale, duplicate, or cannot
    /// be durably recorded under the exact immutable binding.
    #[allow(clippy::needless_pass_by_value)]
    pub fn prepare_bootstrap(
        &mut self,
        preparation: BootstrapPreparation,
    ) -> Result<(), QualificationReplayLedgerError> {
        self.verify_healthy()?;
        let result = self.prepare_bootstrap_inner(&preparation);
        self.finish_bootstrap(result)
    }

    /// # Errors
    ///
    /// Returns an error unless one current prepared offer atomically accepts
    /// the supplied daemon challenge.
    pub fn arm_bootstrap(
        &mut self,
        offer_id: [u8; 32],
        daemon_challenge: [u8; 32],
    ) -> Result<BootstrapArmed, QualificationReplayLedgerError> {
        self.verify_healthy()?;
        let result = self.arm_bootstrap_inner(offer_id, daemon_challenge);
        self.finish_bootstrap(result)
    }

    /// # Errors
    ///
    /// Returns an error unless one current armed offer atomically records the
    /// exact proof digest.
    pub fn mark_bootstrap_issued(
        &mut self,
        offer_id: [u8; 32],
        proof_sha256: [u8; 32],
    ) -> Result<(), QualificationReplayLedgerError> {
        self.verify_healthy()?;
        let result = self.mark_bootstrap_issued_inner(offer_id, proof_sha256);
        self.finish_bootstrap(result)
    }

    /// # Errors
    ///
    /// Returns an error unless the issued row matches all supplied proof
    /// identifiers and remains within its admission window.
    pub fn load_bootstrap_issued(
        &mut self,
        offer_id: [u8; 32],
        daemon_challenge: [u8; 32],
        proof_sha256: [u8; 32],
    ) -> Result<BootstrapArmed, QualificationReplayLedgerError> {
        self.verify_healthy()?;
        let result = self.load_bootstrap_issued_inner(offer_id, daemon_challenge, proof_sha256);
        self.finish_bootstrap(result)
    }

    /// # Errors
    ///
    /// Returns an error unless the matching issued offer has already been
    /// persisted as the sealed run-bootstrap proof.
    pub fn mark_bootstrap_consumed(
        &mut self,
        offer_id: [u8; 32],
        daemon_challenge: [u8; 32],
        proof_sha256: [u8; 32],
    ) -> Result<(), QualificationReplayLedgerError> {
        self.verify_healthy()?;
        let result = self.mark_bootstrap_consumed_inner(offer_id, daemon_challenge, proof_sha256);
        self.finish_bootstrap(result)
    }

    fn prepare_bootstrap_inner(
        &mut self,
        preparation: &BootstrapPreparation,
    ) -> Result<(), QualificationReplayLedgerError> {
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| QualificationReplayLedgerError)?;
        if !preparation.valid() || !is_current(preparation, system_now()?) {
            return Err(QualificationReplayLedgerError);
        }
        reject_existing_bootstrap_replay(&transaction, preparation)?;
        insert_immutable_run(&transaction, preparation.binding())?;
        transaction
            .execute(
                "INSERT INTO bootstrap_arms (offer_id, context_id, context_nonce, source_revision, workflow_run_id, namespace_sha256, candidate_sha256, raw_tuple_sha256, manifest_sha256, profile_sha256, issued_at, expires_at, run_not_after, max_run_duration, state) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                params![
                    preparation.offer_id().as_slice(),
                    preparation.context_id().as_slice(),
                    preparation.nonce().as_slice(),
                    preparation.binding().source_revision().as_slice(),
                    preparation.binding().workflow_run_id(),
                    preparation.binding().namespace_sha256().as_slice(),
                    preparation.binding().candidate_sha256().as_slice(),
                    preparation.binding().raw_v3_tuple_sha256().as_slice(),
                    preparation.binding().manifest_sha256().as_slice(),
                    preparation.binding().profile_sha256().as_slice(),
                    preparation.issued_at(),
                    preparation.expires_at(),
                    preparation.run_not_after(),
                    preparation.max_run_duration(),
                    PREPARED,
                ],
            )
            .map_err(|_| QualificationReplayLedgerError)?;
        transaction
            .commit()
            .map_err(|_| QualificationReplayLedgerError)
    }

    fn arm_bootstrap_inner(
        &mut self,
        offer_id: [u8; 32],
        daemon_challenge: [u8; 32],
    ) -> Result<BootstrapArmed, QualificationReplayLedgerError> {
        if offer_id == [0; 32] || daemon_challenge == [0; 32] {
            return Err(QualificationReplayLedgerError);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| QualificationReplayLedgerError)?;
        let now = system_now()?;
        let changed = transaction
            .execute(
                "UPDATE bootstrap_arms SET state=?1, daemon_challenge=?2 WHERE offer_id=?3 AND state=?4 AND issued_at<=?5 AND expires_at>?5 AND run_not_after>?5",
                params![ARMED, daemon_challenge.as_slice(), offer_id.as_slice(), PREPARED, now],
            )
            .map_err(|_| QualificationReplayLedgerError)?;
        if changed != 1 {
            return Err(QualificationReplayLedgerError);
        }
        transaction
            .commit()
            .map_err(|_| QualificationReplayLedgerError)?;
        self.load_armed(offer_id, daemon_challenge)
    }

    fn mark_bootstrap_issued_inner(
        &mut self,
        offer_id: [u8; 32],
        proof_sha256: [u8; 32],
    ) -> Result<(), QualificationReplayLedgerError> {
        if offer_id == [0; 32] || proof_sha256 == [0; 32] {
            return Err(QualificationReplayLedgerError);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| QualificationReplayLedgerError)?;
        let now = system_now()?;
        let changed = transaction.execute(
            "UPDATE bootstrap_arms SET state=?1, proof_sha256=?2 WHERE offer_id=?3 AND state=?4 AND issued_at<=?5 AND expires_at>?5 AND run_not_after>?5",
            params![ISSUED, proof_sha256.as_slice(), offer_id.as_slice(), ARMED, now],
        ).map_err(|_| QualificationReplayLedgerError)?;
        (changed == 1)
            .then_some(())
            .ok_or(QualificationReplayLedgerError)?;
        transaction
            .commit()
            .map_err(|_| QualificationReplayLedgerError)
    }

    fn load_bootstrap_issued_inner(
        &self,
        offer_id: [u8; 32],
        daemon_challenge: [u8; 32],
        proof_sha256: [u8; 32],
    ) -> Result<BootstrapArmed, QualificationReplayLedgerError> {
        if offer_id == [0; 32] || daemon_challenge == [0; 32] || proof_sha256 == [0; 32] {
            return Err(QualificationReplayLedgerError);
        }
        let armed = self.connection.query_row(
            "SELECT offer_id, context_id, context_nonce, source_revision, workflow_run_id, namespace_sha256, candidate_sha256, raw_tuple_sha256, manifest_sha256, profile_sha256, issued_at, expires_at, run_not_after, max_run_duration, daemon_challenge FROM bootstrap_arms WHERE offer_id=?1 AND daemon_challenge=?2 AND proof_sha256=?3 AND state=?4",
            params![offer_id.as_slice(), daemon_challenge.as_slice(), proof_sha256.as_slice(), ISSUED],
            stored_armed,
        ).map_err(|_| QualificationReplayLedgerError)?;
        let armed = armed_from_stored(armed)?;
        is_current_armed(&armed, system_now()?)
            .then_some(armed)
            .ok_or(QualificationReplayLedgerError)
    }

    fn mark_bootstrap_consumed_inner(
        &mut self,
        offer_id: [u8; 32],
        daemon_challenge: [u8; 32],
        proof_sha256: [u8; 32],
    ) -> Result<(), QualificationReplayLedgerError> {
        if offer_id == [0; 32] || daemon_challenge == [0; 32] || proof_sha256 == [0; 32] {
            return Err(QualificationReplayLedgerError);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| QualificationReplayLedgerError)?;
        let changed = transaction.execute(
            "UPDATE bootstrap_arms SET state=?1 WHERE offer_id=?2 AND daemon_challenge=?3 AND proof_sha256=?4 AND state=?5 AND EXISTS (SELECT 1 FROM run_bootstraps r WHERE r.context_id=bootstrap_arms.context_id AND r.context_nonce=bootstrap_arms.context_nonce AND r.source_revision=bootstrap_arms.source_revision AND r.workflow_run_id=bootstrap_arms.workflow_run_id AND r.namespace_sha256=bootstrap_arms.namespace_sha256) AND EXISTS (SELECT 1 FROM replay_keys k WHERE k.domain=1 AND k.replay_key=bootstrap_arms.context_id AND k.source_revision=bootstrap_arms.source_revision AND k.workflow_run_id=bootstrap_arms.workflow_run_id AND k.namespace_sha256=bootstrap_arms.namespace_sha256) AND EXISTS (SELECT 1 FROM replay_keys k WHERE k.domain=2 AND k.replay_key=bootstrap_arms.context_nonce AND k.source_revision=bootstrap_arms.source_revision AND k.workflow_run_id=bootstrap_arms.workflow_run_id AND k.namespace_sha256=bootstrap_arms.namespace_sha256)",
            params![CONSUMED, offer_id.as_slice(), daemon_challenge.as_slice(), proof_sha256.as_slice(), ISSUED],
        ).map_err(|_| QualificationReplayLedgerError)?;
        (changed == 1)
            .then_some(())
            .ok_or(QualificationReplayLedgerError)?;
        transaction
            .commit()
            .map_err(|_| QualificationReplayLedgerError)
    }

    fn load_armed(
        &self,
        offer_id: [u8; 32],
        daemon_challenge: [u8; 32],
    ) -> Result<BootstrapArmed, QualificationReplayLedgerError> {
        self.connection.query_row(
            "SELECT offer_id, context_id, context_nonce, source_revision, workflow_run_id, namespace_sha256, candidate_sha256, raw_tuple_sha256, manifest_sha256, profile_sha256, issued_at, expires_at, run_not_after, max_run_duration, daemon_challenge FROM bootstrap_arms WHERE offer_id=?1 AND daemon_challenge=?2 AND state=?3",
            params![offer_id.as_slice(), daemon_challenge.as_slice(), ARMED],
            stored_armed,
        ).map_err(|_| QualificationReplayLedgerError).and_then(armed_from_stored)
    }

    fn finish_bootstrap<T>(
        &mut self,
        result: Result<T, QualificationReplayLedgerError>,
    ) -> Result<T, QualificationReplayLedgerError> {
        if result.is_err() || self.verify_healthy().is_err() {
            self.poisoned = true;
            return Err(QualificationReplayLedgerError);
        }
        result
    }
}

#[cfg(test)]
#[path = "bootstrap_tests.rs"]
mod tests;
