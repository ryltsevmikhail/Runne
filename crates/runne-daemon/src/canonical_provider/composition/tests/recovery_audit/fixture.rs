use runne_application::provider::ProviderAuthorityIssueRequest;
use runne_domain::id::{AttemptId, ConversationId, EventLogLineageId, TaskRunId};
use runne_provider::{
    ModelRef, PreparedProviderRecord as ContractPreparedProviderRecord, PreparedRequest,
    ProviderCall, ProviderCallDigestVersion, ProviderCallId, ProviderId, ProviderStreamId,
};
use runne_store::provider::{
    MarkProviderStreaming, PreparedProviderRecord, ProviderAuthorityIssueOutcome,
};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

pub(super) use super::super::managed_test_connection;
use super::super::*;
pub(super) use super::snapshot::{Snapshot, assert_unchanged_except, snapshot, table_columns};

pub(super) struct Harness {
    _directory: tempfile::TempDir,
    pub(super) db_path: String,
    authority: [u8; 16],
    lineage: EventLogLineageId,
    generation: u64,
    profile_digest: [u8; 32],
    provenance: DaemonActivationProvenance,
    /// Owner-private bootstrap (authority lock) alive for the whole scenario.
    _verified: VerifiedOwnerPrivateConfig,
    pub(super) store: StoreTransaction,
    conversation_service: Arc<dyn ConversationTextCommandService>,
    prohibited: Arc<dyn ProhibitedContentPort>,
    keyring: Arc<dyn ProviderJournalKeyring>,
}

impl Harness {
    pub(super) async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut config = crate::config::ConfigurationSnapshot::from_defaults(
            &BuiltInDefaults::new(directory.path()),
        );
        config.provider_activation = ProviderActivation::from_binding(
            ProviderActivationBindingV1::openai_responses_text_v1(),
        );
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

    pub(super) async fn compose(&self) -> Arc<DaemonCanonicalProviderService> {
        self.compose_at_generation(self.generation).await
    }

    pub(super) async fn compose_at_generation(
        &self,
        generation: u64,
    ) -> Arc<DaemonCanonicalProviderService> {
        self.try_compose_at_generation(generation).await.unwrap()
    }

    pub(super) async fn try_compose_at_generation(
        &self,
        generation: u64,
    ) -> Result<Arc<DaemonCanonicalProviderService>, DaemonError> {
        let effect =
            runne_daemon_openai_effect::effect_from_loopback_fixture(reqwest::Client::new())
                .unwrap()
                .0;
        let effect = crate::canonical_provider::openai_effect_adapter(effect);
        let decorator = Arc::new(|store: Arc<SqliteProviderExecutionStore>, _: u64| {
            let execution: Arc<dyn ProviderExecutionStore> = store.clone();
            let terminal: Arc<dyn ProviderTerminalPersistence> = store;
            (execution, terminal)
        });
        DaemonCanonicalProviderService::compose(DaemonCanonicalProviderComposition {
            db_path: self.db_path.clone(),
            dispatch_connection: self.writer_connection(),
            execution_connection: self.writer_connection(),
            credential_connection: self.writer_connection(),
            runtime_authority_id: self.authority,
            runtime_generation: generation,
            activation_provenance: self.provenance,
            expected_profile_digest: self.profile_digest,
            conversation_store: self.store.clone(),
            conversation_service: Arc::clone(&self.conversation_service),
            prohibited_content: Arc::clone(&self.prohibited),
            profile: openai_profile(),
            adapter_factory: fixture_adapter_factory(),
            provider_id: "openai",
            model_id: runne_provider_openai::OPENAI_MODEL_ID,
            model_revision: runne_provider_openai::OPENAI_MODEL_REVISION,
            scope: "provider.openai.responses.text",
            credential_id: ProviderCredentialId::OpenAi,
            dependencies: ProtectedProviderDependencyCapsule::from_loopback_fixture(
                effect,
                Arc::clone(&self.keyring),
                decorator,
                Arc::new(crate::canonical_provider::credential_versions::fixture_native),
            ),
        })
        .await
    }

    pub(super) fn issue_incomplete(
        &self,
        service: &DaemonCanonicalProviderService,
        seed: u8,
        streaming: bool,
    ) -> runne_provider::DispatchAttemptId {
        let call = ProviderCall::new(
            ProviderCallId::from_bytes([seed; 16]),
            ModelRef::new(
                ProviderId::new("fixture-provider").unwrap(),
                format!("fixture-model-{seed}"),
                format!("v{seed}"),
            )
            .unwrap(),
            [seed.wrapping_add(1); 32],
            1_024,
            serde_json::json!({ "seed": seed }),
        )
        .unwrap();
        let prepared =
            PreparedRequest::from_call_for_digest_version(&call, ProviderCallDigestVersion::V2)
                .unwrap();
        let record = PreparedProviderRecord {
            call_id: call.call_id(),
            call_digest_version: prepared.request_ref().digest_version(),
            prepared_digest: *prepared.request_ref().as_bytes(),
            render_digest: *prepared.render_digest(),
            profile_digest: service.profile.profile_digest(),
        };
        service
            .dispatch_store
            .persist_prepared(&service.launch_capability, &record)
            .unwrap();
        let ProviderAuthorityIssueOutcome::Winner(admitted) = service
            .execution_store
            .issue(
                &service.launch_capability,
                &ProviderAuthorityIssueRequest {
                    provider_id: call.model_ref().provider_id().clone(),
                    principal_id: "local-owner".into(),
                    conversation_id: ConversationId::from_bytes([seed.wrapping_add(20); 16]),
                    taskrun_id: TaskRunId::from_bytes([seed.wrapping_add(40); 16]),
                    execution_attempt_id: AttemptId::from_bytes([seed.wrapping_add(60); 16]),
                    prepared: ContractPreparedProviderRecord {
                        call_id: record.call_id,
                        call_digest_version: record.call_digest_version,
                        prepared_digest: record.prepared_digest,
                        render_digest: record.render_digest,
                        profile_digest: record.profile_digest,
                    },
                    pricing_revision_digest: service.profile.pricing_revision_digest(),
                    requested_input_tokens: 512,
                    requested_output_tokens: 1_024,
                    max_cost_micros: 50_000,
                    currency: "USD".into(),
                    provider_idempotency_key: format!("rotation-incomplete-{seed}"),
                },
            )
            .unwrap()
        else {
            panic!("fixture admission must win");
        };
        if streaming {
            service
                .dispatch_store
                .mark_streaming(&MarkProviderStreaming {
                    attempt_id: admitted.claim().attempt_id,
                    fencing_token: admitted.claim().fencing_token,
                    stream_id: ProviderStreamId::from_bytes([seed.wrapping_add(80); 16]),
                })
                .unwrap();
        }
        admitted.claim().attempt_id
    }
}

include!("fixture_accessors.rs");
