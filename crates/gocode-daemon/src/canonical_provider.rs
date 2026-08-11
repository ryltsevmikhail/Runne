//! Concrete OpenAI canonical execution composition owned by the daemon root.
use std::path::PathBuf;
use std::sync::Arc;

use gocode_application::conversation_text_service::ConversationTextCommandService;
use gocode_application::ports::ConversationRepository;
use gocode_application::prohibited_content::ProhibitedContentPort;
use gocode_application::provider::{
    ProviderAdmissionError, ProviderCoordinatorRequest, ProviderExecutionStore,
    ProviderJournalKeyBinding,
};
use gocode_domain::conversation::ConversationEvent;
use gocode_provider::{
    ModelRef, ProviderCall, ProviderCallId, ProviderCapability, ProviderId, ProviderInputRole,
    ProviderStreamEventKind, ProviderTerminalDisposition, ProviderTextInput, ProviderUsage,
    StreamCursor, WithheldTailStore,
};
use gocode_provider_openai::{OPENAI_MODEL_ID, OPENAI_MODEL_REVISION, OpenAiResponsesTextProfile};
use gocode_runtime::canonical_provider_execution::{
    CanonicalProviderExecutionError, CanonicalProviderExecutionJob,
    CanonicalProviderExecutionService,
};
use gocode_runtime::provider_execution::{
    ConversationProviderTerminalApplication, ProviderEventJournalContext,
    ProviderTerminalPersistence, RuntimeProviderExecution, RuntimeProviderExecutionError,
};
use gocode_runtime::provider_redaction::{
    ProhibitedContentCredentialMatcher, ProviderEventRedactionBoundary,
};
use gocode_secure_store::{
    NativeProviderCredentialStore, NativeWithheldTailStore, ProviderCredentialAccessPolicy,
    ProviderCredentialStatus, ProviderCredentialStore, ProviderJournalKeyStatus,
    ProviderJournalKeyring,
};
use gocode_store::provider::{
    ProviderCoordinatorOutcome, ProviderRuntimeAuthorityConfig,
    SqliteProviderCredentialLifecycleStore, SqliteProviderDispatchCoordinator,
    SqliteProviderDispatchStore, SqliteProviderExecutionStore, SqliteProviderRecoveryStore,
};
use gocode_store::store::StoreTransaction;
use sha2::{Digest, Sha256};

use crate::error::DaemonError;
use crate::provider_activation::ProviderActivation;

mod activation_provenance;
mod composition;
mod composition_telemetry;
mod credential_versions;
mod execution;
mod loopback_tail;
mod projection;
mod readiness;
mod recovery;
mod runtime_store;

use loopback_tail::LoopbackWithheldTailStore;

pub(crate) use activation_provenance::DaemonActivationProvenance;
pub(crate) use composition::DaemonCanonicalOpenAiComposition;
pub use composition::{DaemonCanonicalOpenAiService, compose_selected_provider};
pub use readiness::{OpenAiReadinessError, OpenAiReadinessEvidence};

pub(crate) type RuntimeStoreDecorator = dyn Fn(
        Arc<SqliteProviderExecutionStore>,
        u64,
    ) -> (
        Arc<dyn ProviderExecutionStore>,
        Arc<dyn ProviderTerminalPersistence>,
    ) + Send
    + Sync;
