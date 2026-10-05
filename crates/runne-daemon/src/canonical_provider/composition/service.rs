use super::*;

#[path = "secondary_effects_metadata.rs"]
mod secondary_effects_metadata;
pub(in crate::canonical_provider) use secondary_effects_metadata::SecondaryEffectsMetadata;

pub struct DaemonCanonicalProviderService {
    pub(in crate::canonical_provider) dispatch_store: Arc<SqliteProviderDispatchStore>,
    pub(in crate::canonical_provider) execution_store: Arc<SqliteProviderExecutionStore>,
    pub(in crate::canonical_provider) credential_store: Arc<SqliteProviderCredentialLifecycleStore>,
    pub(in crate::canonical_provider) quota_store: Arc<runne_provider_quota::QuotaStateStore>,
    #[allow(dead_code, reason = "used by protected macOS verification")]
    pub(in crate::canonical_provider) enrollment_store_authority:
        Option<runne_provider::CredentialEnrollmentStoreAuthority>,
    pub(in crate::canonical_provider) credential_readback: Option<Arc<dyn ProviderCredentialReadback>>,
    pub(in crate::canonical_provider) credential_status: runne_secure_store::ProviderCredentialStatus,
    pub(in crate::canonical_provider) credential_enrollment_control:
        Option<Arc<crate::application::provider_credential_enrollment::DaemonProviderCredentialEnrollmentControl>>,
    pub(in crate::canonical_provider) runtime_store: Arc<runtime_store::DaemonProviderRuntimeStore>,
    pub(in crate::canonical_provider) conversation_store: StoreTransaction,
    pub(in crate::canonical_provider) conversation_service: Arc<dyn ConversationTextCommandService>,
    pub(in crate::canonical_provider) adapter: Arc<dyn CanonicalProviderEffect>,
    pub(in crate::canonical_provider) profile: Arc<SharedTextProviderProfile>,
    pub(in crate::canonical_provider) tool_profile: Option<Arc<SharedTextProviderProfile>>,
    #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
    pub(in crate::canonical_provider) tool_profile_grant:
        Option<runne_store::provider::ProviderSecondaryProfileGrant>,
    pub(in crate::canonical_provider) provider_id: std::borrow::Cow<'static, str>,
    pub(in crate::canonical_provider) model_id: std::borrow::Cow<'static, str>,
    pub(in crate::canonical_provider) model_revision: std::borrow::Cow<'static, str>,
    pub(in crate::canonical_provider) keyring: Arc<dyn ProviderJournalKeyring>,
    pub(in crate::canonical_provider) remote_fact_authenticator:
        Arc<dyn runne_application::provider::ProviderRemoteFactAuthenticator>,
    pub(in crate::canonical_provider) prohibited_content: Arc<dyn ProhibitedContentPort>,
    pub(in crate::canonical_provider) trust: Option<crate::application::trust_delivery::DeliveryTrustGate>,
    pub(in crate::canonical_provider) scanner_store: Arc<SqliteProviderRecoveryStore>,
    pub(in crate::canonical_provider) tail_store: Arc<dyn WithheldTailStore>,
    pub(in crate::canonical_provider) runtime_authority_id: [u8; 16],
    pub(in crate::canonical_provider) database_generation: u64,
    pub(in crate::canonical_provider) runtime_generation: u64,
    pub(in crate::canonical_provider) fencing_token: u64,
    pub(in crate::canonical_provider) launch_capability: ProviderRuntimeLaunchCapability,
    pub(in crate::canonical_provider) renewal_dispatch_gate: super::dispatch_gate::ProviderDispatchGate,
    pub(in crate::canonical_provider) recovery_registry: Arc<runne_observability::operational::RecoveryObservationRegistry>,
    pub(in crate::canonical_provider) secondary_profile:
        Option<super::super::execution::SecondaryProfileRoute>,
    pub(in crate::canonical_provider) secondary_effects_metadata:
        Option<SecondaryEffectsMetadata>,
    pub(in crate::canonical_provider) saved_remote_gate:
        Arc<super::super::saved_remote_gate::SavedRemoteBlockingGate>,
}
