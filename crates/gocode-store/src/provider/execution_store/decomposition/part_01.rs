use std::fmt::Write as _;
use std::path::Path;
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(test)]
use std::sync::Barrier;
use std::sync::{Arc, Mutex};

use gocode_application::provider::{
    ProviderAdmissionError, ProviderAuthorityIssueRequest, ProviderBudgetUtilization,
    ProviderEffectAuthorityRef, ProviderEncryptedPayload, ProviderExecutionError,
    ProviderExecutionStore, ProviderJournalAppendOutcome, ProviderJournalAppendRequest,
    ProviderJournalKeyBinding, ProviderPollRequest, ProviderTerminalCommitOutcome,
    ProviderTerminalOutboxRecord, ProviderTerminalPricingBinding,
};
use gocode_domain::id::{AttemptId, ConversationId, TaskRunId};
use gocode_provider::{
    DispatchAttemptId, ProviderCallDigestVersion, ProviderDispatchClaim, ProviderRepositoryState,
};
use gocode_runtime::provider_execution::{
    ProviderTerminalCommitRequest, ProviderTerminalPersistence,
};
use rand::RngCore;
use rand::rngs::OsRng;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use super::authority_config::ProviderRuntimeAuthorityConfig;
use super::authority_state::{RuntimeAuthorityState, binding_kind, load_utilization};
use super::effect_start::{ProviderEffectStartReceipt, start_effect};
use crate::schema::{
    ConnectionMode, ManagedConnection, apply_migrations, open_managed_connection,
    publication_from_managed, readiness_from_managed,
};

const PROVIDER_EXECUTION_SEMANTIC_V1: &[u8] = b"GOCODE_PROVIDER_EXECUTION_SEMANTIC_V1\0";

/// SQLite runtime-owned atomic provider authority issuer.
pub struct SqliteProviderExecutionStore {
    pub(super) connection: Mutex<ManagedConnection>,
    now: Arc<dyn Fn() -> i64 + Send + Sync>,
    #[cfg(test)]
    fail_effect_readback: AtomicBool,
    #[cfg(test)]
    effect_receipt_pause: Mutex<Option<(Arc<Barrier>, Arc<Barrier>)>>,
}

/// Concrete store-owned admission returned only after durable read-back.
///
/// ```compile_fail
/// use gocode_store::provider::DurableProviderAdmission;
///
/// let _ = DurableProviderAdmission {};
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableProviderAdmission {
    authority_ref: ProviderEffectAuthorityRef,
    runtime_generation: u64,
    claim: ProviderDispatchClaim,
}

impl DurableProviderAdmission {
    /// Durable authority reference.
    pub const fn authority_ref(&self) -> ProviderEffectAuthorityRef {
        self.authority_ref
    }

    /// Runtime generation read from the committed admission.
    pub const fn runtime_generation(&self) -> u64 {
        self.runtime_generation
    }

    /// Exact durable claim.
    pub const fn claim(&self) -> &ProviderDispatchClaim {
        &self.claim
    }

    /// Consumes the store-owned admission into its exact claim.
    pub fn into_claim(self) -> ProviderDispatchClaim {
        self.claim
    }
}

/// Concrete SQLite issuance result; winner values are store-owned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderAuthorityIssueOutcome {
    /// Newly committed admission loaded back from the authoritative database.
    Winner(Box<DurableProviderAdmission>),
    /// Exact replay with no new dispatch authority.
    Existing { state: ProviderRepositoryState },
}
