use std::{borrow::Cow, sync::Arc};

use runne_application::conversation_text_service::ConversationTextCommandService;
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_provider_quota::QuotaStateStore;
use runne_secure_store::ProviderCredentialId;
use runne_store::store::StoreTransaction;

use super::super::{DaemonActivationProvenance, ProviderEffectFactory, SharedTextProviderProfile};
use crate::application::workspace_internal::ProtectedProviderDependencyCapsule;

pub(crate) struct DaemonCanonicalProviderComposition {
    pub(crate) db_path: String,
    pub(crate) dispatch_connection: runne_store::schema::ManagedConnection,
    pub(crate) execution_connection: runne_store::schema::ManagedConnection,
    pub(crate) credential_connection: runne_store::schema::ManagedConnection,
    pub(crate) runtime_authority_id: [u8; 16],
    pub(crate) runtime_generation: u64,
    pub(crate) activation_provenance: DaemonActivationProvenance,
    pub(crate) expected_profile_digest: [u8; 32],
    pub(crate) conversation_store: StoreTransaction,
    pub(crate) conversation_service: Arc<dyn ConversationTextCommandService>,
    pub(crate) prohibited_content: Arc<dyn ProhibitedContentPort>,
    pub(crate) trust: Option<crate::application::trust_delivery::DeliveryTrustGate>,
    pub(crate) profile: Arc<SharedTextProviderProfile>,
    pub(crate) adapter_factory: Arc<ProviderEffectFactory>,
    pub(crate) provider_id: Cow<'static, str>,
    pub(crate) model_id: Cow<'static, str>,
    pub(crate) model_revision: Cow<'static, str>,
    pub(crate) scope: Cow<'static, str>,
    pub(crate) credential_id: ProviderCredentialId,
    pub(crate) quota_store: Arc<QuotaStateStore>,
    pub(crate) dependencies: ProtectedProviderDependencyCapsule,
}
