//! Durable provider prepare and single-dispatch coordination.

mod authority_config;
mod authority_state;
mod credential_lifecycle;
mod dispatch_binding;
mod dispatch_coordinator;
mod dispatch_store;
mod effect_port;
mod effect_start;
mod execution_store;
pub mod operational_telemetry;
mod recovery_store;
mod runtime_launch_capability;

pub use dispatch_binding::{
    CredentialDispatchAuthority, CredentialDispatchBinding, ProviderExecutionBinding,
    VersionedProviderExecutionBinding,
};
pub(crate) use dispatch_binding::{OnlineCredentialDispatchBinding, OnlineEffectStartBinding};
/// The coordinator is the sole public V26 effect-start route.
///
/// ```compile_fail
/// use runne_store::provider::{
///     OnlineCredentialDispatchBinding, OnlineEffectStartBinding,
///     ProviderOnlineEffectStartReceipt,
/// };
/// ```
pub use dispatch_coordinator::{ProviderCoordinatorOutcome, SqliteProviderDispatchCoordinator};

pub use authority_config::ProviderRuntimeAuthorityConfig;
pub use credential_lifecycle::CredentialProvision;
pub use credential_lifecycle::SUBSCRIPTION_LOCAL_TOKEN_BUDGET;
pub use credential_lifecycle::SqliteProviderCredentialLifecycleStore;
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub use credential_lifecycle::online_claim_test_support;
pub use dispatch_store::{
    MarkProviderStreaming, PersistPreparedOutcome, PreparedProviderRecord, ProviderClaimOutcome,
    ProviderDispatchClaim, ProviderDispatchRecord, ProviderDispatchState, ProviderStoreError,
    RecoveryCasOutcome, SettleProviderDispatch, SqliteProviderDispatchStore,
};
pub use effect_port::{ProviderEffectPort, ProviderReadyEffect};
pub use effect_start::ProviderEffectStartReceipt;
pub use execution_store::{
    DurableProviderAdmission, ProviderAuthorityIssueOutcome, SqliteProviderExecutionStore,
};
pub use recovery_store::SqliteProviderRecoveryStore;
pub use runtime_launch_capability::ProviderRuntimeLaunchCapability;
