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

pub use dispatch_binding::{
    CredentialDispatchAuthority, CredentialDispatchBinding, ProviderExecutionBinding,
    VersionedProviderExecutionBinding,
};
pub use dispatch_coordinator::{ProviderCoordinatorOutcome, SqliteProviderDispatchCoordinator};

pub use authority_config::ProviderRuntimeAuthorityConfig;
pub use credential_lifecycle::CredentialProvision;
pub use credential_lifecycle::SqliteProviderCredentialLifecycleStore;
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
