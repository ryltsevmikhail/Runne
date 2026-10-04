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
mod final_send_authority;
pub mod operational_telemetry;
mod recovery_store;
mod runtime_launch_capability;

pub(crate) use execution_store::record_taskrun_provider_cancel_fence;
pub(crate) use execution_store::taskrun_provider_cancel_fence_matches;
pub(crate) use execution_store::{
    ProviderRemoteObservationState, RemoteArtifactAckKind,
    load_remote_effects_snapshot_in_transaction, load_unknown_effects_snapshot,
    read_remote_observation_in_transaction, validate_remote_artifact_ack_for_readiness,
    validate_remote_artifact_pending_application_for_readiness,
};

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
pub(crate) use credential_lifecycle::credential_safe_snapshot_in_transaction;
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
    DurableProviderAdmission, ProviderAuthorityIssueOutcome, ProviderSecondaryProfileGrant,
    SqliteProviderExecutionStore,
};
pub use final_send_authority::ProviderFinalSendAuthority;
pub use recovery_store::SqliteProviderRecoveryStore;
pub use runtime_launch_capability::ProviderRuntimeLaunchCapability;
