use runne_application::provider::ProviderCoordinatorRequest;
use runne_domain::id::{AttemptId, ConversationId, TaskRunId};
use runne_provider::{
    ModelRef, ProviderCall, ProviderCallId, ProviderCapability, ProviderId, ProviderInputRole,
    ProviderTextInput,
};
use runne_provider_chat_completions::{
    ChatCompletionsProfile, ChatCompletionsRenderer, generic_profile,
};
use runne_store::provider::{
    ProviderRuntimeAuthorityConfig, SqliteProviderCredentialLifecycleStore,
    SqliteProviderDispatchStore, SqliteProviderExecutionStore,
};

pub struct Fixture {
    pub(crate) _database: crate::validated_reopen::ProviderTestDatabase,
    pub(crate) dispatch: SqliteProviderDispatchStore,
    pub(crate) execution: SqliteProviderExecutionStore,
    pub(crate) credential: SqliteProviderCredentialLifecycleStore,
    pub(crate) launch: runne_store::provider::ProviderRuntimeLaunchCapability,
    pub(crate) request: ProviderCoordinatorRequest,
    pub(crate) profile: ChatCompletionsProfile,
}

pub(crate) fn response_body(model: &str) -> Vec<u8> {
    format!(
        "data: {{\"id\":\"chatcmpl_fixture_1\",\"object\":\"chat.completion.chunk\",\"created\":1720000000,\"model\":\"{model}\",\"choices\":[{{\"index\":0,\"delta\":{{\"role\":\"assistant\"}},\"finish_reason\":null}}]}}\n\ndata: {{\"id\":\"chatcmpl_fixture_1\",\"object\":\"chat.completion.chunk\",\"created\":1720000001,\"model\":\"{model}\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"hello\"}},\"finish_reason\":null}}]}}\n\ndata: {{\"id\":\"chatcmpl_fixture_1\",\"object\":\"chat.completion.chunk\",\"created\":1720000002,\"model\":\"{model}\",\"choices\":[{{\"index\":0,\"delta\":{{}},\"finish_reason\":\"stop\"}}],\"usage\":{{\"prompt_tokens\":7,\"completion_tokens\":3,\"total_tokens\":10,\"prompt_tokens_details\":{{\"cached_tokens\":1}},\"completion_tokens_details\":{{\"reasoning_tokens\":0}}}}}}\n\ndata: [DONE]\n\n"
    )
    .into_bytes()
}

pub(crate) fn fixture_with_ttl(provider: &str, authority_ttl_seconds: u64) -> Fixture {
    let database = crate::validated_reopen::ProviderTestDatabase::new("chat-effect");
    let dispatch = database.dispatch();
    let execution = database.execution();
    let credential = crate::online_credential_fixture::credential(&database, provider, 61);
    let profile = generic_profile(provider).unwrap();
    let digest = profile.profile_digest();
    let pricing_digest = profile.pricing_revision_digest();
    let extension = ChatCompletionsRenderer::new(profile.clone())
        .unwrap()
        .binding_extension()
        .clone();
    let launch = execution
        .activate_runtime_launch(&ProviderRuntimeAuthorityConfig {
            runtime_authority_id: [1; 16],
            database_generation: 1,
            principal_id: "principal".into(),
            owner_id: "owner".into(),
            scope: "provider.dispatch".into(),
            generation: 1,
            fencing_token: 1,
            capability_grant_id: "grant".into(),
            capability_revision: 1,
            capability_allowed: true,
            capability_revocation_epoch: 1,
            approval_id: "approval".into(),
            approval_revision: 1,
            approval_allowed: true,
            approval_revocation_epoch: 1,
            profile_digest: digest,
            pricing_revision_digest: profile.pricing_revision_digest(),
            activation_binding_kind:
                runne_application::provider::ProviderLeaseBindingKind::ProtectedV2,
            activation_binding_digest: [4; 32],
            token_budget_limit: 10_000,
            cost_budget_limit_micros: 1_000_000,
            authority_ttl_seconds,
            lease_ttl_seconds: 600,
        })
        .unwrap();
    crate::online_proof::arm(&execution, 1);
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([41; 16]),
        ModelRef::new(
            ProviderId::new(provider).unwrap(),
            profile.model_id(),
            profile.model_revision(),
        )
        .unwrap(),
        [5; 32],
        64,
        extension,
    )
    .unwrap()
    .with_text_inputs(vec![
        ProviderTextInput::new(ProviderInputRole::User, "hello").unwrap(),
    ])
    .unwrap()
    .with_required_capabilities(vec![ProviderCapability::Streaming]);
    Fixture {
        _database: database,
        dispatch,
        execution,
        credential,
        launch,
        profile: profile.clone(),
        request: ProviderCoordinatorRequest {
            call,
            principal_id: "principal".into(),
            conversation_id: ConversationId::from_bytes([6; 16]),
            taskrun_id: TaskRunId::from_bytes([7; 16]),
            execution_attempt_id: AttemptId::from_bytes([8; 16]),
            profile_digest: digest,
            pricing_revision_digest: pricing_digest,
            requested_input_tokens: 32,
            requested_output_tokens: 64,
            max_cost_micros: 10_000,
            currency: profile.currency().into(),
            provider_idempotency_key: "chat-effect-valid".into(),
        },
    }
}
