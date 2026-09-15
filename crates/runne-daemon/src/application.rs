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
    REPLAY_ENVELOPE_CURSOR_BINDING_OVERHEAD_BYTES, REPLAY_FRAME_CAPACITY_BYTES,
    REPLAY_PAGE_CAPACITY_BYTES, ReplayAuthorizationLease, ReplayAuthorizationPort,
    ReplayAuthorizationRequest, ReplayError, ReplayService, ReplayStorePort,
    validate_replay_reader_capacity,
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
    RuntimeTaskRunHost, TokioRuntimeContext,
};
use runne_security::SecretBroker;
use runne_store::local_session::SqliteBootstrapReservationStore;
use runne_store::replay_store::ReplayStore;
use runne_store::schema::ensure_event_log_lineage_id;
use runne_store::store::StoreTransaction;

type SqliteTaskRunService = TaskRunService<StoreTransaction, StoreTransaction, StoreTransaction>;
type SqliteConversationService = ConversationService<StoreTransaction, StoreTransaction>;

mod executable_identity;
mod http_startup;
mod http_startup_support;
#[cfg(feature = "desktop-protected")]
pub(crate) mod native_process;
#[cfg(feature = "desktop-protected")]
pub(crate) mod native_process_provider;
#[cfg(feature = "desktop-protected")]
mod native_process_registry;
#[cfg(not(feature = "desktop-protected"))]
mod process_unavailable;
pub(crate) mod provider_credential_enrollment;
pub(crate) mod provider_credential_verification;
mod provider_selection;
mod provider_startup;
mod provider_status;
mod quota;
mod readiness;
mod replay_authorization;
#[cfg(all(feature = "test-support", feature = "desktop-protected"))]
pub(crate) mod root_admission_test_support;
#[cfg(not(feature = "desktop-protected"))]
mod root_admission_unavailable;
#[cfg(feature = "desktop-protected")]
#[doc(hidden)]
pub(crate) mod root_handle_admission;
mod runtime_connection;
mod shutdown;
mod startup;
#[cfg(test)]
mod tests;
pub(crate) mod workspace_internal;

use runtime_connection::open_runtime_connection;
pub use startup::DaemonApplication;
pub(crate) use startup::VerifiedOwnerPrivateConfig;
