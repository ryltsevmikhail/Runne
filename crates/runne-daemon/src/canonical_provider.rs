//! Concrete OpenAI canonical execution composition owned by the daemon root.
use std::path::PathBuf;
use std::sync::Arc;

use runne_application::conversation_text_service::ConversationTextCommandService;
use runne_application::ports::ConversationRepository;
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_application::provider::{
    ProviderAdmissionError, ProviderCoordinatorRequest, ProviderExecutionStore,
    ProviderJournalKeyBinding,
};
use runne_domain::conversation::ConversationEvent;
use runne_provider::{
    ModelRef, ProviderCall, ProviderCallId, ProviderCapability, ProviderId, ProviderInputRole,
    ProviderPort, ProviderStreamEventKind, ProviderTerminalDisposition, ProviderTextInput,
    ProviderUsage, StreamCursor, TextProviderProfile, WithheldTailStore,
};
use runne_runtime::canonical_provider_execution::{
    CanonicalProviderExecutionError, CanonicalProviderExecutionJob,
    CanonicalProviderExecutionService,
};
use runne_runtime::provider_execution::{
    ConversationProviderTerminalApplication, ProviderEventJournalContext,
    ProviderTerminalPersistence, RuntimeProviderExecution, RuntimeProviderExecutionError,
};
use runne_runtime::provider_redaction::{
    ProhibitedContentCredentialMatcher, ProviderEventRedactionBoundary,
};
use runne_secure_store::{
    NativeWithheldTailStore, ProviderCredentialAccessPolicy, ProviderCredentialReadback,
    ProviderCredentialStatus, ProviderJournalKeyStatus, ProviderJournalKeyring,
};
use runne_store::provider::{
    ProviderCoordinatorOutcome, ProviderEffectPort, ProviderRuntimeAuthorityConfig,
    ProviderRuntimeLaunchCapability, SqliteProviderCredentialLifecycleStore,
    SqliteProviderDispatchCoordinator, SqliteProviderDispatchStore, SqliteProviderExecutionStore,
    SqliteProviderRecoveryStore,
};
use runne_store::store::StoreTransaction;
use sha2::{Digest, Sha256};

use crate::error::DaemonError;

mod activation_provenance;
mod composition;
mod composition_enrollment;
mod composition_telemetry;
mod credential_reader;
#[cfg(test)]
pub(crate) mod credential_versions;
mod dispatch_binding;
mod dispatch_gate;
mod dynamic_readiness;
mod effect_adapter;
#[path = "canonical_provider/composition/effects_projection.rs"]
mod effects_projection;
mod execution;
#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
pub(crate) use execution::{D2ProviderRound, D2ProviderRoundOutcome, D2ToolTerminalRef};
mod execution_authority;
mod execution_cancellation;
mod execution_diagnostics;
mod historical_model_resolver;
mod loopback_tail;
mod openai_profile;
mod optional_catalog;
mod projection;
mod provider_failure_recovery;
pub(crate) mod readiness;
mod recovery;
mod recovery_authorizer;
mod redaction_diagnostics;
mod runtime_launch;
mod runtime_store;
mod saved_remote_apply;
mod saved_remote_gate;
mod saved_remote_observe;
mod saved_remote_recovery;
mod selected_provider;
mod shared_profile;

pub(crate) use execution_cancellation::foreground_cancellation_result;

use loopback_tail::LoopbackWithheldTailStore;

pub(crate) use activation_provenance::DaemonActivationProvenance;
pub(crate) use composition::DaemonCanonicalProviderComposition;
pub use composition::DaemonCanonicalProviderService;
pub(crate) use effect_adapter::{
    CanonicalProviderEffect, ProviderEffectFactory, deepseek_effect_adapter,
    local_engine_effect_adapter, native_effect_adapter, openai_effect_adapter,
    radius_effect_adapter, responses_effect_adapter,
};
pub(crate) use historical_model_resolver::CompiledHistoricalProviderModelResolver;
pub(crate) use openai_profile::OpenAiTextProviderProfile;
pub(crate) use optional_catalog::VerifiedSecondaryCatalog;
pub(crate) use readiness::probe_provider_readiness;
pub use readiness::{ProviderReadinessError, ProviderReadinessEvidence};
pub use selected_provider::compose_selected_provider;
pub(crate) use shared_profile::SharedTextProviderProfile;

pub(crate) type RuntimeStoreDecorator = dyn Fn(
        Arc<SqliteProviderExecutionStore>,
        u64,
    ) -> (
        Arc<dyn ProviderExecutionStore>,
        Arc<dyn ProviderTerminalPersistence>,
    ) + Send
    + Sync;
