use runne_application::provider::ProviderCoordinatorRequest;
use runne_provider::{
    ModelRef, ProviderCall, ProviderCallId, ProviderCapability, ProviderId, ProviderInputRole,
    ProviderTextInput,
};
use runne_provider_responses_wire::{ResponsesProfile, ResponsesProvider};
use runne_store::provider::{
    ProviderRuntimeAuthorityConfig, SqliteProviderCredentialLifecycleStore,
    SqliteProviderDispatchStore, SqliteProviderExecutionStore,
};

pub struct Fixture {
    pub(crate) _database: crate::validated_reopen::ProviderTestDatabase,
    pub(crate) _taskrun_store: runne_store::store::StoreTransaction,
    pub(crate) dispatch: SqliteProviderDispatchStore,
    pub(crate) execution: SqliteProviderExecutionStore,
    pub(crate) credential: SqliteProviderCredentialLifecycleStore,
    pub(crate) launch: runne_store::provider::ProviderRuntimeLaunchCapability,
    pub(crate) request: ProviderCoordinatorRequest,
    pub(crate) profile: ResponsesProfile,
}

pub(crate) fn response_body() -> Vec<u8> {
    br#"event: response.created
data: {"type":"response.created","sequence_number":0,"response":{"id":"resp_fixture_1","model":"grok-4","object":"response","created_at":1720000000}}

event: response.output_text.delta
data: {"type":"response.output_text.delta","sequence_number":1,"delta":"hello"}

event: response.completed
data: {"type":"response.completed","sequence_number":2,"response":{"id":"resp_fixture_1","model":"grok-4","status":"completed","usage":{"input_tokens":7,"output_tokens":3,"input_token_details":{"cached_tokens":1},"output_token_details":{"reasoning_tokens":0}}}}

"#
    .to_vec()
}

pub(crate) fn fixture() -> Fixture {
    let database = crate::validated_reopen::ProviderTestDatabase::new("responses-effect");
    let started =
        crate::provider_taskrun_start::begin(database.path(), [1; 16], "principal", "hello");
    let dispatch = database.dispatch();
    let execution = database.execution();
    let credential = crate::online_credential_fixture::credential(&database, "xai", 31);
    let profile = ResponsesProfile::new(ResponsesProvider::Xai, "grok-4")
        .with_model_revision("2026-09-14")
        .with_binding_extension(serde_json::json!({"marker":"responses-effect"}))
        .with_pricing_revision_digest([3; 32]);
    let digest = profile.profile_digest();
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
            pricing_revision_digest: [3; 32],
            activation_binding_kind:
                runne_application::provider::ProviderLeaseBindingKind::ProtectedV2,
            activation_binding_digest: [4; 32],
            token_budget_limit: 10_000,
            cost_budget_limit_micros: 1_000_000,
            authority_ttl_seconds: 120,
            lease_ttl_seconds: 600,
        })
        .unwrap();
    crate::online_proof::arm(&execution, 1);
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([41; 16]),
        ModelRef::new(ProviderId::new("xai").unwrap(), "grok-4", "2026-09-14").unwrap(),
        [5; 32],
        64,
        serde_json::json!({"marker":"responses-effect"}),
    )
    .unwrap()
    .with_text_inputs(vec![
        ProviderTextInput::new(ProviderInputRole::User, "hello").unwrap(),
    ])
    .unwrap()
    .with_required_capabilities(vec![ProviderCapability::Streaming]);
    Fixture {
        _database: database,
        _taskrun_store: started._store,
        dispatch,
        execution,
        credential,
        launch,
        profile,
        request: ProviderCoordinatorRequest {
            call,
            principal_id: "principal".into(),
            conversation_id: started.receipt.conversation_id,
            taskrun_id: started.receipt.taskrun_id,
            execution_attempt_id: started.receipt.attempt_id,
            profile_digest: digest,
            pricing_revision_digest: [3; 32],
            requested_input_tokens: 32,
            requested_output_tokens: 64,
            max_cost_micros: 10_000,
            currency: "USD".into(),
            provider_idempotency_key: "responses-effect-valid".into(),
        },
    }
}
