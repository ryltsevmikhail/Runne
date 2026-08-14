//! Single-file durable fixture authority for cross-promotion stage nonce claims.

use std::cell::{Cell, RefCell};
use std::path::{Path, PathBuf};

use crate::{
    AuthorityError, CommandId, InMemoryPromotionStore, Mutation, PromotionId, PromotionStore,
    RawStageTransitionRequest, SigningAuthorizedReceipt, StageTransitionStore,
    ThresholdFixtureStoreBinding, TransactionOutcome,
};

#[path = "store_durable_authority_root.rs"]
mod authority_root;
#[path = "store_durable_authority_wire.rs"]
pub mod authority_wire;

/// Atomic root ledger: every promotion record and every stage nonce lives under one protected
/// fixture file and lease. Production does not provision this fixture-only persistence path.
pub struct DurableFixturePromotionAuthority {
    pub(crate) path: PathBuf,
    pub(crate) binding: ThresholdFixtureStoreBinding,
    pub(crate) authority_instance: crate::Digest,
    pub(crate) lease: crate::store_durable_lease::Lease,
    pub(crate) lock: RefCell<()>,
    pub(crate) poisoned: Cell<bool>,
    #[cfg(all(test, feature = "fixture-only"))]
    pub(crate) publication_failpoint:
        Cell<Option<crate::publication_effect_failpoint::PublicationEffectFailpoint>>,
}

impl DurableFixturePromotionAuthority {
    /// Create a new root ledger from all initialized in-memory fixture promotions.
    ///
    /// # Errors
    /// Returns an error for unsafe paths, empty authority state, or failed durable initialization.
    pub fn create_from_in_memory(
        path: impl AsRef<Path>,
        binding: ThresholdFixtureStoreBinding,
        source: &InMemoryPromotionStore,
    ) -> Result<Self, AuthorityError> {
        if source.entries.is_empty() {
            return Err(AuthorityError::InvalidTransition);
        }
        let this = Self::open(path, binding, source.authority_instance)?;
        this.create(source)?;
        Ok(this)
    }

    /// Create a new root ledger from disjoint initialized fixture stores.
    ///
    /// # Errors
    /// Returns an error when any promotion id is duplicated or durable setup fails.
    pub fn create_from_in_memories(
        path: impl AsRef<Path>,
        binding: ThresholdFixtureStoreBinding,
        sources: &[&InMemoryPromotionStore],
    ) -> Result<Self, AuthorityError> {
        let claimed = sources
            .iter()
            .filter(|source| !source.rc2_effect_ledger.is_empty())
            .map(|source| source.authority_instance)
            .collect::<std::collections::BTreeSet<_>>();
        if claimed.len() > 1 {
            return Err(AuthorityError::BindingMismatch);
        }
        let authority_instance = claimed
            .into_iter()
            .next()
            .unwrap_or_else(|| InMemoryPromotionStore::default().authority_instance);
        let mut merged = InMemoryPromotionStore::with_authority_instance(authority_instance);
        for source in sources {
            let mut source = (*source).clone();
            if source.authority_instance != authority_instance {
                source.rebind_unclaimed_authority(authority_instance)?;
            }
            for (id, record) in &source.entries {
                if merged.entries.insert(id.clone(), record.clone()).is_some() {
                    return Err(AuthorityError::BindingMismatch);
                }
            }
            merged
                .rc2_effect_ledger
                .merge_from(&source.rc2_effect_ledger)
                .map_err(|_| AuthorityError::BindingMismatch)?;
            merged
                .publication_effect_ledger
                .merge_from(&source.publication_effect_ledger)
                .map_err(|_| AuthorityError::BindingMismatch)?;
        }
        Self::create_from_in_memory(path, binding, &merged)
    }

    /// Reopen one exact root ledger; all nonce claims are recovered atomically with records.
    ///
    /// # Errors
    /// Returns an error for corrupt, unsafe, or differently-bound durable state.
    pub fn reopen(
        path: impl AsRef<Path>,
        binding: ThresholdFixtureStoreBinding,
    ) -> Result<Self, AuthorityError> {
        let mut this = Self::open(path, binding, crate::Digest::from_bytes([0; 32]))?;
        let store = this.load()?;
        this.authority_instance = store.authority_instance;
        Ok(this)
    }

    fn open(
        path: impl AsRef<Path>,
        binding: ThresholdFixtureStoreBinding,
        authority_instance: crate::Digest,
    ) -> Result<Self, AuthorityError> {
        Ok(Self {
            path: path.as_ref().into(),
            binding,
            authority_instance,
            lease: crate::store_durable_lease::Lease::acquire(path.as_ref())?,
            lock: RefCell::new(()),
            poisoned: Cell::new(false),
            #[cfg(all(test, feature = "fixture-only"))]
            publication_failpoint: Cell::new(None),
        })
    }
}

impl PromotionStore for DurableFixturePromotionAuthority {
    fn transact(
        &mut self,
        id: &PromotionId,
        expected: u64,
        command: CommandId,
        mutation: Mutation,
    ) -> Result<TransactionOutcome, AuthorityError> {
        let _guard = self.lock.borrow_mut();
        let mut store = self.load()?;
        let result = store.transact(id, expected, command, mutation)?;
        self.save(&store)?;
        Ok(result)
    }

    fn reserve_verify_signed(
        &mut self,
        id: &PromotionId,
        expected: u64,
        command: CommandId,
        bundle: &crate::FixturePrevalidatedSignedBundle,
    ) -> Result<SigningAuthorizedReceipt, AuthorityError> {
        let _guard = self.lock.borrow_mut();
        let mut store = self.load()?;
        let result = store.reserve_verify_signed(id, expected, command, bundle)?;
        self.save(&store)?;
        Ok(result)
    }
}

impl StageTransitionStore for DurableFixturePromotionAuthority {
    fn verify_and_commit_stage_transition(
        &mut self,
        request: RawStageTransitionRequest<'_>,
    ) -> Result<TransactionOutcome, AuthorityError> {
        let _guard = self.lock.borrow_mut();
        let mut store = self.load()?;
        let result = store.verify_and_commit_stage_transition(request)?;
        self.save(&store)?;
        Ok(result)
    }
}
