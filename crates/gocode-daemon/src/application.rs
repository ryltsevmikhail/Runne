//! Concrete daemon composition root.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::bootstrap::{BootstrapOutcome, bootstrap};
use crate::canonical_provider::{
    DaemonActivationProvenance, DaemonCanonicalOpenAiComposition, DaemonCanonicalOpenAiService,
    compose_selected_provider,
};
use crate::client_profile::PublishedClientProfileV3;
use crate::config::ConfigurationSnapshot;
use crate::error::DaemonError;
use crate::provider_activation::ProviderActivation;
use crate::recovery::{RecoveryState, enumerate_recovery_tasks};
use crate::shutdown::{RuntimeTaskSupervisor, graceful_shutdown};
use gocode_api::{
    ApiActor, ApiPrincipalId, ExecutableIdentityV1, ProtectedActivationKeys,
    ProtectedLaunchRequestV1, ProtectedLaunchRequestV2, ProtectedReadyV1, ProtectedReadyV2,
    ProviderActivationReadinessV1, RuntimeSessionBinding, StableRuntimeBinding,
    StableRuntimeBindingV1,
};
use gocode_application::conversation_service::ConversationService;
use gocode_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
use gocode_application::local_session::LocalSessionService;
use gocode_application::ports::RuntimeAuthorityId;
use gocode_application::prohibited_content::ProhibitedContentPort;
use gocode_application::replay_service::{
    REPLAY_ENVELOPE_CURSOR_BINDING_OVERHEAD_BYTES, REPLAY_FRAME_CAPACITY_BYTES,
    REPLAY_PAGE_CAPACITY_BYTES, ReplayAuthorizationLease, ReplayAuthorizationPort,
    ReplayAuthorizationRequest, ReplayError, ReplayService, ReplayStorePort,
    validate_replay_reader_capacity,
};
use gocode_application::service::TaskRunService;
use gocode_domain::event::Sensitivity;
use gocode_http::admission::AdmissionState;
use gocode_http::conversations::ConversationHttpState;
use gocode_http::health::{HealthState, RecoveryState as HttpRecoveryState};
use gocode_http::limits::LimitsConfig;
use gocode_http::operational_telemetry::OperationalTelemetryHttpState;
use gocode_http::replay::{ReplayHttpBinding, ReplayHttpState};
use gocode_http::runtime_profile::RuntimeProfileHttpState;
use gocode_http::secure_local_host::LocalRuntimeTlsHost;
use gocode_http::task_runs::TaskRunHttpState;
use gocode_runtime::config::RuntimeConfig;
use gocode_runtime::controller::{RuntimeController, ShutdownMode, ShutdownOutcome};
use gocode_runtime::handle::RuntimeHandle;
use gocode_runtime::{
    DeterministicTextProvider, Runtime, RuntimeCanonicalConversationHost, RuntimeGenerationId,
    RuntimeTaskRunHost, TokioRuntimeContext,
};
use gocode_security::SecretBroker;
use gocode_store::replay_store::ReplayStore;
use gocode_store::schema::ensure_event_log_lineage_id;
use gocode_store::store::StoreTransaction;

type SqliteTaskRunService = TaskRunService<StoreTransaction, StoreTransaction, StoreTransaction>;
type SqliteConversationService = ConversationService<StoreTransaction, StoreTransaction>;

mod http_startup;
mod provider_startup;
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
