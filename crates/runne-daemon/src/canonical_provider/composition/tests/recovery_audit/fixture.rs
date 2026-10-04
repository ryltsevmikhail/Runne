use runne_application::commands::{
    BeginClaimedConversationTextInput, BeginConversationTextInput, SubmitTaskRunInput,
};
use runne_application::ports::{ExecutionNodeId, TaskRunAssignmentIdentity};
use runne_application::provider::ProviderAuthorityIssueRequest;
use runne_application::provider::ProviderSecondaryProfileGrantSpec;
use runne_application::service::{ClaimTaskRunInput, TaskRunService};
use runne_domain::id::{AttemptId, ConversationId, EventLogLineageId, TaskRunId, WorkspaceId};
use runne_domain::task_run::TaskRunInput;
use runne_provider::{
    ModelRef, PreparedProviderRecord as ContractPreparedProviderRecord, ProviderCall,
    ProviderCallId, ProviderCapability, ProviderId, ProviderInputRole, ProviderStreamId,
    ProviderTextInput, TextProviderProfile,
};
use runne_store::provider::PreparedProviderRecord;
use std::borrow::Cow;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

use super::super::*;
pub(super) use super::super::{managed_test_connection, try_managed_test_connection};
pub(super) use super::snapshot::{Snapshot, assert_unchanged_except, snapshot, table_columns};

pub(in crate::canonical_provider::composition::tests) struct Harness {
    _directory: tempfile::TempDir,
    pub(in crate::canonical_provider::composition::tests) db_path: String,
    authority: [u8; 16],
    lineage: EventLogLineageId,
    generation: u64,
    profile_digest: [u8; 32],
    provenance: DaemonActivationProvenance,
    /// Owner-private bootstrap (authority lock) alive for the whole scenario.
    _verified: VerifiedOwnerPrivateConfig,
    pub(in crate::canonical_provider::composition::tests) store: StoreTransaction,
    conversation_service: Arc<dyn ConversationTextCommandService>,
    prohibited: Arc<dyn ProhibitedContentPort>,
    keyring: Arc<dyn ProviderJournalKeyring>,
}

impl Harness {
    pub(in crate::canonical_provider::composition::tests) async fn new() -> Self {
        Self::new_with_activation(ProviderActivation::from_binding(
            ProviderActivationBindingV1::openai_responses_text_v1(),
        ))
        .await
    }

    pub(in crate::canonical_provider::composition::tests) async fn new_with_profile(
        profile: &crate::canonical_provider::composition::tests::online_dispatch::profile_fixture::PrimaryProfileFixture,
    ) -> Self {
        Self::new_with_activation(profile.activation.clone()).await
    }

    async fn new_with_activation(activation: ProviderActivation) -> Self {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut config = crate::config::ConfigurationSnapshot::from_defaults(
            &BuiltInDefaults::new(directory.path()),
        );
        config.provider_activation = activation;
        let profile_digest = *config.provider_activation.binding().profile_digest();
        let db_path = config.db_path.clone();
        let bootstrap = bootstrap(&config).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(
            std::path::Path::new(&db_path).parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let lineage = runne_store::schema::ensure_event_log_lineage_id(&bootstrap.db_conn).unwrap();
        let authority = bootstrap.authority_id;
        let generation = bootstrap.launch_generation;
        let verified = VerifiedOwnerPrivateConfig::from_test_parts(config, bootstrap);
        let provenance = DaemonActivationProvenance::from_verified_owner_private_config(&verified);
        let prohibited: Arc<dyn ProhibitedContentPort> =
            Arc::new(SecretBroker::new().prohibited_content_guard());
        let store = StoreTransaction::open_with_connections(
            &db_path,
            managed_test_connection(
                &db_path,
                authority,
                lineage,
                runne_store::schema::ConnectionMode::ValidatedReopen,
            ),
            managed_test_connection(
                &db_path,
                authority,
                lineage,
                runne_store::schema::ConnectionMode::Reader,
            ),
            RuntimeAuthorityId(hex::encode(authority)),
            Arc::clone(&prohibited),
        )
        .unwrap();
        let conversation_service: Arc<dyn ConversationTextCommandService> =
            Arc::new(ConversationTextService::new(
                store.clone(),
                store.clone(),
                RuntimeAuthorityId(hex::encode(authority)),
                Arc::clone(&prohibited),
            ));
        seed_canonical_workspace(
            &store,
            "018f2e3a-7000-7000-8000-000000000093".parse().unwrap(),
        );
        Self {
            _directory: directory,
            db_path,
            authority,
            lineage,
            generation,
            profile_digest,
            provenance,
            _verified: verified,
            store,
            conversation_service,
            prohibited,
            keyring: Arc::new(Keyring::default()),
        }
    }

    pub(in crate::canonical_provider::composition::tests) async fn compose(
        &self,
    ) -> Arc<DaemonCanonicalProviderService> {
        self.try_compose_openai_provider_at_generation(self.generation)
            .await
            .unwrap()
    }

    pub(in crate::canonical_provider::composition::tests) async fn compose_with_catalog(
        &self,
        catalog: crate::canonical_provider::VerifiedSecondaryCatalog,
    ) -> Arc<DaemonCanonicalProviderService> {
        self.try_compose_with_catalog(catalog).await.unwrap()
    }

    pub(super) async fn try_compose_with_catalog(
        &self,
        catalog: crate::canonical_provider::VerifiedSecondaryCatalog,
    ) -> Result<Arc<DaemonCanonicalProviderService>, DaemonError> {
        self.try_compose_at_generation_with_catalog(self.generation, Some(catalog))
            .await
    }

    pub(in crate::canonical_provider::composition::tests) fn catalog_for_test(
        &self,
        spec: ProviderSecondaryProfileGrantSpec,
    ) -> crate::canonical_provider::VerifiedSecondaryCatalog {
        crate::canonical_provider::VerifiedSecondaryCatalog::from_test_spec(
            spec,
            self.authority,
            &self.db_path,
        )
    }

    pub(super) async fn compose_at_generation(
        &self,
        generation: u64,
    ) -> Arc<DaemonCanonicalProviderService> {
        self.try_compose_openai_provider_at_generation(generation)
            .await
            .unwrap()
    }

    pub(super) async fn try_compose_at_generation(
        &self,
        generation: u64,
    ) -> Result<Arc<DaemonCanonicalProviderService>, DaemonError> {
        self.try_compose_openai_provider_at_generation(generation)
            .await
    }

    pub(super) async fn try_compose_at_generation_with_catalog(
        &self,
        generation: u64,
        secondary_catalog: Option<crate::canonical_provider::VerifiedSecondaryCatalog>,
    ) -> Result<Arc<DaemonCanonicalProviderService>, DaemonError> {
        self.try_compose_configured(generation, secondary_catalog, None, true, None)
            .await
    }

    pub(in crate::canonical_provider::composition::tests) async fn try_compose_with_mock_secondary(
        &self,
        catalog: crate::canonical_provider::VerifiedSecondaryCatalog,
        effect: Arc<dyn CanonicalProviderEffect>,
        primary_fixture: bool,
    ) -> Result<Arc<DaemonCanonicalProviderService>, DaemonError> {
        self.try_compose_configured(
            self.generation,
            Some(catalog),
            Some(effect),
            primary_fixture,
            None,
        )
        .await
    }

    pub(super) fn revoke_secondary_spec(&self, spec: ProviderSecondaryProfileGrantSpec) {
        let store = SqliteProviderExecutionStore::open_with_connection(
            &self.db_path,
            self.writer_connection(),
        )
        .unwrap();
        let profile = openai_profile();
        let scope = Cow::Borrowed("provider.openai.responses.text");
        let launch = crate::canonical_provider::runtime_launch::activate(
            &store,
            self.authority,
            self.generation,
            &self.provenance,
            profile.as_ref(),
            &scope,
        )
        .unwrap();
        let grant = store
            .install_secondary_profile_grant(&launch, spec)
            .unwrap();
        store
            .revoke_secondary_profile_grant(&launch, &grant)
            .unwrap();
    }
}

include!("fixture_issue_incomplete.rs");
include!("fixture_accessors.rs");
include!("fixture_compose.rs");
include!("fixture_rotation.rs");
