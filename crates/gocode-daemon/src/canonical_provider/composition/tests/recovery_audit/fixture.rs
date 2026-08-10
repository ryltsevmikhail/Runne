use gocode_application::provider::ProviderAuthorityIssueRequest;
use gocode_domain::id::{AttemptId, ConversationId, EventLogLineageId, TaskRunId};
use gocode_provider::{
    ModelRef, PreparedProviderRecord as ContractPreparedProviderRecord, PreparedRequest,
    ProviderCall, ProviderCallDigestVersion, ProviderCallId, ProviderId, ProviderStreamId,
};
use gocode_store::provider::{
    MarkProviderStreaming, PreparedProviderRecord, ProviderAuthorityIssueOutcome,
};

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
    pub(super) store: StoreTransaction,
    conversation_service: Arc<dyn ConversationTextCommandService>,
    prohibited: Arc<dyn ProhibitedContentPort>,
    keyring: Arc<dyn ProviderJournalKeyring>,
}

impl Harness {
    pub(super) async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut config = crate::config::ConfigurationSnapshot::from_defaults(
            &BuiltInDefaults::new(directory.path()),
        );
        config.provider_activation = ProviderActivation::from_binding(
            ProviderActivationBindingV1::openai_responses_text_v1(),
        );
        let profile_digest = *config.provider_activation.binding().profile_digest();
        let db_path = config.db_path.clone();
        let bootstrap = bootstrap(&config).unwrap();
        let authority = bootstrap.authority_id;
        let lineage =
            gocode_store::schema::ensure_event_log_lineage_id(&bootstrap.db_conn).unwrap();
        let generation = bootstrap.launch_generation;
        let provenance = DaemonActivationProvenance::from_verified_owner_private_config(
            &VerifiedOwnerPrivateConfig::from_test_parts(config, bootstrap),
        );
        let prohibited: Arc<dyn ProhibitedContentPort> =
            Arc::new(SecretBroker::new().prohibited_content_guard());
        let store = StoreTransaction::open(
            &db_path,
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
        Self {
            _directory: directory,
            db_path,
            authority,
            lineage,
            generation,
            profile_digest,
            provenance,
            store,
            conversation_service,
            prohibited,
            keyring: Arc::new(Keyring::default()),
        }
    }

    pub(super) async fn compose(&self) -> Arc<DaemonCanonicalOpenAiService> {
        self.compose_at_generation(self.generation).await
    }

    pub(super) fn open_runtime_connection(&self) -> rusqlite::Connection {
        open_test_runtime_connection(&self.db_path, self.authority, self.lineage)
    }

    pub(super) async fn compose_at_generation(
        &self,
        generation: u64,
    ) -> Arc<DaemonCanonicalOpenAiService> {
        let effect =
            gocode_daemon_openai_effect::effect_from_loopback_fixture(reqwest::Client::new())
                .unwrap()
                .0;
        let decorator = Arc::new(|store: Arc<SqliteProviderExecutionStore>, _: u64| {
            let execution: Arc<dyn ProviderExecutionStore> = store.clone();
            let terminal: Arc<dyn ProviderTerminalPersistence> = store;
            (execution, terminal)
        });
        DaemonCanonicalOpenAiService::compose(DaemonCanonicalOpenAiComposition {
            db_path: self.db_path.clone(),
            dispatch_connection: self.open_runtime_connection(),
            execution_connection: self.open_runtime_connection(),
            runtime_authority_id: self.authority,
            runtime_generation: generation,
            activation_provenance: self.provenance,
            expected_profile_digest: self.profile_digest,
            conversation_store: self.store.clone(),
            conversation_service: Arc::clone(&self.conversation_service),
            prohibited_content: Arc::clone(&self.prohibited),
            dependencies: ProtectedProviderDependencyCapsule::from_loopback_fixture(
                effect,
                Arc::clone(&self.keyring),
                decorator,
            ),
        })
        .await
        .unwrap()
    }

    pub(super) fn issue_incomplete(
        &self,
        service: &DaemonCanonicalOpenAiService,
        seed: u8,
        streaming: bool,
    ) -> gocode_provider::DispatchAttemptId {
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
        service.dispatch_store.persist_prepared(&record).unwrap();
        let ProviderAuthorityIssueOutcome::Winner(admitted) = service
            .execution_store
            .issue(&ProviderAuthorityIssueRequest {
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
            })
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

    pub(super) const fn generation(&self) -> u64 {
        self.generation
    }

    pub(super) fn terminal_application(
        &self,
    ) -> gocode_runtime::provider_execution::ConversationProviderTerminalApplication<StoreTransaction>
    {
        gocode_runtime::provider_execution::ConversationProviderTerminalApplication::new(
            self.store.clone(),
            Arc::clone(&self.conversation_service),
        )
    }

    pub(super) fn keyring(&self) -> Arc<dyn ProviderJournalKeyring> {
        Arc::clone(&self.keyring)
    }

    pub(super) fn prohibited(&self) -> Arc<dyn ProhibitedContentPort> {
        Arc::clone(&self.prohibited)
    }

    pub(super) fn begin(
        &self,
    ) -> (
        ApplicationCommandContext,
        gocode_application::ports::TextGenerationReceipt,
    ) {
        let conversation_id = "018f2e3a-7000-7000-8000-000000000091".parse().unwrap();
        let create = command_context("018f2e3a-7000-7000-8000-000000000092", "audit-create");
        ConversationService::new(
            self.store.clone(),
            self.store.clone(),
            RuntimeAuthorityId(hex::encode(self.authority)),
        )
        .create_from_application(
            &create,
            CreateConversationInput {
                conversation_id,
                workspace_id: "018f2e3a-7000-7000-8000-000000000093"
                    .parse::<WorkspaceId>()
                    .unwrap(),
                command_id: create.command_id,
                idempotency_key: create.idempotency_key.clone(),
            },
        )
        .unwrap();
        let begin = command_context("018f2e3a-7000-7000-8000-000000000094", "audit-begin");
        let started = self
            .conversation_service
            .begin_text(
                &begin,
                BeginConversationTextInput {
                    conversation_id,
                    expected_version: 1,
                    text: MessageText::new("fixture input").unwrap(),
                },
            )
            .unwrap();
        (begin, started)
    }
}
