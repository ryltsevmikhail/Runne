use runne_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ProhibitedContentPort,
};
use runne_application::provider::{ProviderAdmissionError, ProviderCoordinatorRequest};
use runne_provider::CredentialLifecycleError;
use runne_provider::{
    DispatchError, DispatchRequest, ProviderDispatchRepository, ProviderPort,
    ProviderPreEffectRejection, ProviderRepositoryState,
};
use runne_provider_quota::{RemainingState, SubscriptionBudgetAuthority};
use std::sync::Arc;

use super::{
    CredentialDispatchAuthority, MarkProviderStreaming, PreparedProviderRecord,
    ProviderAuthorityIssueOutcome, ProviderEffectPort, ProviderExecutionBinding,
    SqliteProviderDispatchStore, SqliteProviderExecutionStore, VersionedProviderExecutionBinding,
};

mod construction;
mod inflight;
mod rejection;
mod request;
use request::{claim_matches, issue_request};

/// Concrete SQLite provider dispatch outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderCoordinatorOutcome {
    /// New adapter stream was opened.
    Streaming {
        binding: Box<VersionedProviderExecutionBinding>,
    },
    /// Exact replay observed an existing durable state.
    Existing { state: ProviderRepositoryState },
    /// Adapter proved that no external provider effect began.
    RejectedBeforeEffect {
        /// Closed non-secret rejection reason.
        reason: ProviderPreEffectRejection,
    },
    /// Post-claim disposition is ambiguous and progression must freeze.
    Uncertain,
}

/// Concrete coordinator for the authoritative SQLite admission and dispatch path.
pub struct SqliteProviderDispatchCoordinator<'a, P: ?Sized, E: ?Sized> {
    dispatch_store: &'a SqliteProviderDispatchStore,
    execution_store: &'a SqliteProviderExecutionStore,
    credential: CredentialDispatchAuthority<'a>,
    provider: &'a P,
    effect: &'a E,
    prohibited_content: &'a dyn ProhibitedContentPort,
    subscription_provider: bool,
    /// Seed-then-check gate; post-response spending may overshoot by at most
    /// the existing effect semaphore's concurrency minus one requests.
    subscription_budget: Option<Arc<dyn SubscriptionBudgetAuthority>>,
}

include!("dispatch_coordinator/dispatch.rs");
