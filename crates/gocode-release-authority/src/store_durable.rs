//! File-backed, scalar-only, single-writer fixture promotion store.
//!
//! Raw owner stage envelopes require the global durable authority so one nonce registry spans
//! every promotion. This single-record adapter is deliberately not provisioned for that path.

use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::{
    AuthorityError, CommandId, InMemoryPromotionStore, Mutation, PromotionId, PromotionStore,
    SigningAuthorizedReceipt, StageTransitionStore, ThresholdFixtureStoreBinding,
    TransactionOutcome,
};

/// Fail-closed durable fixture adapter. One process owns each protected path at a time.
///
/// Fixture persistence has no configured cryptographic integrity root: its `0600` regular-file
/// boundary is an explicit test-only protected-file assumption. Reopen still rejects any scalar
/// projection that cannot be tied back to stored commands, snapshots, reservations, and trust.
pub struct DurableFixturePromotionStore {
    path: PathBuf,
    binding: ThresholdFixtureStoreBinding,
    _lease: crate::store_durable_lease::Lease,
    pub(crate) lock: RefCell<()>,
}
impl DurableFixturePromotionStore {
    /// Persist a fully verified in-memory setup as scalar state; no authority handle is copied.
    ///
    /// # Errors
    /// Returns an error for missing promotion state or unsafe durable storage.
    pub fn create_from_in_memory(
        path: impl AsRef<Path>,
        binding: ThresholdFixtureStoreBinding,
        source: &InMemoryPromotionStore,
        id: &PromotionId,
    ) -> Result<Self, AuthorityError> {
        let lease = crate::store_durable_lease::Lease::acquire(path.as_ref())?;
        let this = Self {
            path: path.as_ref().into(),
            binding,
            _lease: lease,
            lock: RefCell::new(()),
        };
        let record = source
            .entries
            .get(id)
            .ok_or(AuthorityError::InvalidTransition)?;
        this.create(id, record)?;
        Ok(this)
    }
    /// Reopen a canonical file bound to the exact promotion store profile/bootstrap/version.
    ///
    /// # Errors
    /// Returns an error for unsafe, corrupt, noncanonical, or misbound storage.
    pub fn reopen(
        path: impl AsRef<Path>,
        binding: ThresholdFixtureStoreBinding,
    ) -> Result<Self, AuthorityError> {
        let lease = crate::store_durable_lease::Lease::acquire(path.as_ref())?;
        let this = Self {
            path: path.as_ref().into(),
            binding,
            _lease: lease,
            lock: RefCell::new(()),
        };
        this.load().map(|_| this)
    }
    pub(crate) fn load(
        &self,
    ) -> Result<(PromotionId, crate::store_machine::Record), AuthorityError> {
        crate::store_durable_file::safe_file(&self.path)?;
        let mut bytes = Vec::new();
        File::open(&self.path)
            .map_err(|_| AuthorityError::DurableStateUnavailable)?
            .read_to_end(&mut bytes)
            .map_err(|_| AuthorityError::DurableStateUnavailable)?;
        crate::store_durable_wire::decode(&bytes, &self.binding)
    }
    fn create(
        &self,
        id: &PromotionId,
        record: &crate::store_machine::Record,
    ) -> Result<(), AuthorityError> {
        let bytes = crate::store_durable_wire::encode(&crate::store_durable_wire::from_record(
            &self.binding,
            id,
            record,
        )?)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options
            .open(&self.path)
            .map_err(|_| AuthorityError::DurableStateUnavailable)?;
        output
            .write_all(&bytes)
            .and_then(|()| output.sync_all())
            .map_err(|_| AuthorityError::DurableStateUnavailable)?;
        crate::store_durable_file::safe_file(&self.path)?;
        crate::store_durable_file::sync_parent(&self.path)
    }
    pub(crate) fn save(
        &self,
        id: &PromotionId,
        record: &crate::store_machine::Record,
    ) -> Result<(), AuthorityError> {
        crate::store_durable_file::safe_file(&self.path)?;
        let bytes = crate::store_durable_wire::encode(&crate::store_durable_wire::from_record(
            &self.binding,
            id,
            record,
        )?)?;
        let temp = crate::store_durable_file::temp_file(&self.path, &bytes)?;
        fs::rename(temp, &self.path).map_err(|_| AuthorityError::DurableStateUnavailable)?;
        crate::store_durable_file::safe_file(&self.path)?;
        crate::store_durable_file::sync_parent(&self.path)
    }
    /// Recover only an exact stored verify completion outcome.
    ///
    /// # Errors
    /// Returns an error unless command, revision, and bundle commitment exactly match.
    pub fn completed_outcome(
        &self,
        id: &PromotionId,
        expected: u64,
        command: &CommandId,
        bundle: &crate::FixturePrevalidatedSignedBundle,
    ) -> Result<TransactionOutcome, AuthorityError> {
        let _guard = self.lock.borrow_mut();
        let (stored, record) = self.load()?;
        if stored != *id {
            return Err(AuthorityError::BindingMismatch);
        }
        crate::store_transition::completed(&record, id, expected, command, bundle)
    }
    /// Read the exact persisted snapshot after canonical file validation.
    ///
    /// # Errors
    /// Returns an error for an invalid store binding or absent snapshot.
    pub fn snapshot(
        &self,
        id: &PromotionId,
    ) -> Result<crate::PromotionStateSnapshot, AuthorityError> {
        let _guard = self.lock.borrow_mut();
        let (stored, record) = self.load()?;
        if stored != *id {
            return Err(AuthorityError::BindingMismatch);
        }
        record.snapshot.ok_or(AuthorityError::InvalidTransition)
    }
    /// Claim, remotely acknowledge, then durably settle an exact threshold outbox entry.
    ///
    /// # Errors
    /// Returns an error for stale, divergent, unavailable, or rejected acknowledgement state.
    pub fn acknowledge_threshold_completion(
        &mut self,
        id: &PromotionId,
        expected: u64,
        command: CommandId,
        context: &dyn crate::ThresholdVerificationContext,
    ) -> Result<TransactionOutcome, AuthorityError> {
        let _guard = self.lock.borrow_mut();
        let (stored, mut record) = self.load()?;
        if stored != *id {
            return Err(AuthorityError::BindingMismatch);
        }
        if let Some(tombstone) = &record.threshold_ack {
            let fingerprint = crate::store_command::threshold_ack_fingerprint(
                id,
                expected,
                &command,
                tombstone.admission,
            );
            return (tombstone.claim_revision == expected
                && tombstone.command == command.as_str()
                && tombstone.fingerprint == fingerprint)
                .then(|| tombstone.outcome.clone())
                .ok_or(AuthorityError::CommandReplayDiverged);
        }
        let (claim, fingerprint) =
            crate::store_transition::begin_ack(&mut record, id, expected, &command)?;
        self.save(id, &record)?;
        let proof =
            context.acknowledge_or_recover(&crate::ThresholdAckRequest { claim: &claim })?;
        let outcome = crate::store_transition::settle_ack(
            &mut record,
            id,
            command,
            claim,
            proof,
            fingerprint,
        )?;
        self.save(id, &record)?;
        Ok(outcome)
    }
}
impl PromotionStore for DurableFixturePromotionStore {
    fn transact(
        &mut self,
        id: &PromotionId,
        expected: u64,
        command: CommandId,
        mutation: Mutation,
    ) -> Result<TransactionOutcome, AuthorityError> {
        let _guard = self.lock.borrow_mut();
        let (stored, mut record) = self.load()?;
        if stored != *id {
            return Err(AuthorityError::BindingMismatch);
        }
        let outcome =
            crate::store_transition::transact(&mut record, id, expected, command, mutation)?;
        self.save(id, &record)?;
        Ok(outcome)
    }
    fn reserve_verify_signed(
        &mut self,
        _: &PromotionId,
        _: u64,
        _: CommandId,
        _: &crate::FixturePrevalidatedSignedBundle,
    ) -> Result<SigningAuthorizedReceipt, AuthorityError> {
        // This adapter persists one promotion record only; it cannot atomically consume the
        // global RC2 effect ledger and therefore cannot authorize final RC2 reservation.
        Err(AuthorityError::AuthorityNotProvisioned)
    }
}

impl StageTransitionStore for DurableFixturePromotionStore {
    fn verify_and_commit_stage_transition(
        &mut self,
        _: crate::store::RawStageTransitionRequest<'_>,
    ) -> Result<TransactionOutcome, AuthorityError> {
        Err(AuthorityError::AuthorityNotProvisioned)
    }
}
