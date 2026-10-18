//! Concrete daemon composition root.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::bootstrap::{BootstrapOutcome, bootstrap};
use crate::canonical_provider::{
    DaemonActivationProvenance, DaemonCanonicalProviderComposition, DaemonCanonicalProviderService,
    compose_selected_provider,
};
use crate::client_profile::PublishedClientProfileV3;
use crate::config::ConfigurationSnapshot;
use crate::error::DaemonError;
use crate::provider_activation::ProviderActivation;
use crate::recovery::{RecoveryState, enumerate_recovery_tasks};
use crate::shutdown::{RuntimeTaskSupervisor, graceful_shutdown};
use runne_api::{
    ApiActor, ApiPrincipalId, ExecutableIdentityV1, ProtectedActivationKeys,
    ProtectedLaunchRequestV1, ProtectedLaunchRequestV2, ProtectedReadyV1, ProtectedReadyV2,
    ProviderActivationReadinessV1, RuntimeSessionBinding, StableRuntimeBinding,
    StableRuntimeBindingV1,
};
use runne_application::conversation_service::ConversationService;
use runne_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
use runne_application::local_session::LocalSessionService;
use runne_application::ports::RuntimeAuthorityId;
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_application::replay_service::{
    ReplayAuthorizationLease, ReplayAuthorizationPort, ReplayAuthorizationRequest, ReplayError,
    ReplayService,
};
use runne_application::service::TaskRunService;
use runne_domain::event::Sensitivity;
use runne_http::admission::AdmissionState;
use runne_http::conversations::ConversationHttpState;
use runne_http::health::{HealthState, RecoveryState as HttpRecoveryState};
use runne_http::limits::LimitsConfig;
use runne_http::operational_telemetry::OperationalTelemetryHttpState;
use runne_http::replay::{ReplayHttpBinding, ReplayHttpState};
use runne_http::runtime_profile::RuntimeProfileHttpState;
use runne_http::secure_local_host::LocalRuntimeTlsHost;
use runne_http::task_runs::TaskRunHttpState;
use runne_runtime::config::RuntimeConfig;
use runne_runtime::controller::{RuntimeController, ShutdownMode, ShutdownOutcome};
use runne_runtime::handle::RuntimeHandle;
use runne_runtime::{
    DeterministicTextProvider, Runtime, RuntimeCanonicalConversationHost, RuntimeGenerationId,
    TokioRuntimeContext,
};
use runne_security::SecretBroker;
use runne_store::local_session::SqliteBootstrapReservationStore;
use runne_store::schema::ensure_event_log_lineage_id;
use runne_store::store::StoreTransaction;

type SqliteTaskRunService = TaskRunService<StoreTransaction, StoreTransaction, StoreTransaction>;
#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
type SqliteToolLoopService = TaskRunService<
    StoreTransaction,
    StoreTransaction,
    StoreTransaction,
    runne_application::service::AgentLoopAuthorities<
        tool_authorities::D2ToolLoopAuthority,
        tool_authorities::D2ToolLoopAuthority,
        tool_authorities::D2ToolLoopAuthority,
        tool_authorities::D2ToolLoopAuthority,
        tool_authorities::D2ToolLoopAuthority,
    >,
>;

#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
fn tool_loop_service(
    store: StoreTransaction,
    authority: RuntimeAuthorityId,
    provider: Option<Arc<DaemonCanonicalProviderService>>,
    root_admission: root_handle_admission::RootAdmissionGateway,
) -> Arc<SqliteToolLoopService> {
    use runne_application::service::AgentLoopAuthorities;
    let services =
        tool_authorities::D2ToolLoopAuthority::new(store.clone(), provider, root_admission);
    Arc::new(TaskRunService::with_agent_loop_authorities(
        store.clone(),
        store.clone(),
        store,
        authority,
        AgentLoopAuthorities {
            time: services.clone(),
            retry_schedule: services.clone(),
            wake_evidence: services.clone(),
            reconciliation: services.clone(),
            verification: services,
        },
    ))
}
type SqliteConversationService = ConversationService<StoreTransaction, StoreTransaction>;

#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
pub(crate) mod d2_tool_outcome;
mod exec_taskrun_pre_effect_cancel;
pub(crate) mod exec_taskrun_recovery;
mod exec_taskrun_service;
pub(crate) mod exec_taskrun_worker;
mod executable_identity;
#[cfg(target_os = "linux")]
mod execution_node_lifecycle;
mod http_startup;
mod http_startup_support;
#[cfg(feature = "desktop-protected")]
pub(crate) mod native_process;
#[cfg(feature = "desktop-protected")]
pub(crate) mod native_process_provider;
#[cfg(feature = "desktop-protected")]
mod native_process_registry;
#[cfg(feature = "desktop-protected")]
pub(crate) mod permission_projection;
#[cfg(feature = "desktop-protected")]
pub(crate) mod permission_projection_runtime;
#[cfg(all(feature = "test-support", feature = "desktop-protected"))]
#[cfg(any(test, feature = "test-support"))]
pub mod process_gate_fixture;
#[cfg(not(feature = "desktop-protected"))]
mod process_unavailable;
pub(crate) mod provider_credential_enrollment;
pub(crate) mod provider_credential_verification;
mod provider_selection;
#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
mod tool_authorities;
#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
mod tool_loop_completion;
#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
mod tool_loop_failure;
#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
mod tool_loop_plan;

#[cfg(test)]
pub(crate) fn native_profile_for_fixture(
    binding: &runne_api::ProviderActivationBindingV1,
) -> Result<
    (
        runne_provider_native_wire::NativeWireProfile,
        runne_daemon_native_effect::TrustedNativeEndpoint,
        runne_daemon_native_effect::NativeAuthDescriptor,
    ),
    DaemonError,
> {
    provider_selection::native_profile_for_fixture(binding)
}
mod provider_startup;
mod provider_status;
mod quota;
mod readiness;
mod replay_authorization;
#[cfg(feature = "test-support")]
pub mod replay_authorization_fixture;
#[cfg(all(unix, feature = "test-support", feature = "desktop-protected"))]
#[doc(hidden)]
pub mod root_admission_authority_fixture;
#[cfg(all(unix, feature = "test-support", feature = "desktop-protected"))]
pub(crate) mod root_admission_test_support;
#[cfg(not(feature = "desktop-protected"))]
mod root_admission_unavailable;
#[cfg(feature = "desktop-protected")]
#[doc(hidden)]
pub(crate) mod root_handle_admission;
mod runtime_connection;
mod shutdown;
mod startup;
mod startup_settlement;
#[cfg(test)]
mod tests;
pub(crate) mod trust_delivery;
pub(crate) mod workspace_internal;

use runtime_connection::open_runtime_connection;
pub use startup::DaemonApplication;
pub(crate) use startup::VerifiedOwnerPrivateConfig;
