use gocode_application::provider::{ProviderAuthorityIssueRequest, ProviderLeaseBindingKind};
use gocode_domain::id::{AttemptId, ConversationId, TaskRunId};
use gocode_provider::{
    DispatchRequest, ModelRef, PreparedRequest, ProviderCall, ProviderCallId, ProviderCapability,
    ProviderId, ProviderInputRole, ProviderTextInput,
};
use gocode_provider_openai::{OPENAI_MODEL_ID, OPENAI_MODEL_REVISION};
use gocode_store::provider::{
    DurableProviderAdmission, PreparedProviderRecord, ProviderAuthorityIssueOutcome,
    ProviderRuntimeAuthorityConfig, SqliteProviderDispatchStore, SqliteProviderExecutionStore,
};

fn durable_dispatch(
    profile: &OpenAiResponsesTextProfile,
    effect: &dyn gocode_daemon_openai_effect::OpenAiEffect,
) -> (DispatchRequest, gocode_store::provider::ProviderEffectStartReceipt) {
    let directory = tempfile::tempdir().expect("temporary authoritative store");
    let path = directory.path().join("provider.sqlite");
    let prepared = effect.prepare(&openai_call(profile)).expect("prepared OpenAI request");
    let dispatch_store = SqliteProviderDispatchStore::open(&path).expect("dispatch store");
    dispatch_store
        .persist_prepared(&PreparedProviderRecord {
            call_id: prepared.call().call_id(),
            call_digest_version: prepared.request_ref().digest_version(),
            prepared_digest: *prepared.request_ref().as_bytes(),
            render_digest: *prepared.render_digest(),
            profile_digest: profile.profile_digest(),
        })
        .expect("durable prepared request");
    let execution_store = SqliteProviderExecutionStore::open(&path).expect("execution store");
    execution_store
        .install_runtime_authority(&runtime_authority(profile))
        .expect("runtime authority");
    let admission = match execution_store
        .issue(&authority_issue_request(&prepared, profile))
        .expect("durable provider authority")
    {
        ProviderAuthorityIssueOutcome::Winner(admission) => admission,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("new durable provider authority"),
    };
    receipt_from_admission(execution_store, prepared, admission)
}

fn receipt_from_admission(
    execution_store: SqliteProviderExecutionStore,
    prepared: PreparedRequest,
    admission: Box<DurableProviderAdmission>,
) -> (DispatchRequest, gocode_store::provider::ProviderEffectStartReceipt) {
    let claim = admission.into_claim();
    let request = DispatchRequest::new(prepared, claim.clone()).expect("dispatch claim binding");
    let receipt = execution_store
        .start_effect(&claim)
        .expect("durable effect-start receipt");
    (request, receipt)
}

fn openai_call(profile: &OpenAiResponsesTextProfile) -> ProviderCall {
    ProviderCall::new(
        ProviderCallId::from_bytes([7; 16]),
        ModelRef::new(
            ProviderId::new("openai").expect("provider ID"),
            OPENAI_MODEL_ID,
            OPENAI_MODEL_REVISION,
        )
        .expect("OpenAI model"),
        [9; 32],
        32,
        profile.binding_extension(),
    )
    .expect("provider call")
    .with_text_inputs(vec![
        ProviderTextInput::new(ProviderInputRole::User, "hello").expect("input"),
    ])
    .expect("text inputs")
    .with_required_capabilities(vec![ProviderCapability::Streaming])
}

fn runtime_authority(profile: &OpenAiResponsesTextProfile) -> ProviderRuntimeAuthorityConfig {
    ProviderRuntimeAuthorityConfig {
        runtime_authority_id: [1; 16],
        database_generation: 7,
        principal_id: "principal-1".into(),
        owner_id: "owner-1".into(),
        scope: "provider.dispatch".into(),
        generation: 11,
        fencing_token: 13,
        capability_grant_id: "capability-1".into(),
        capability_revision: 2,
        capability_allowed: true,
        capability_revocation_epoch: 1,
        approval_id: "approval-1".into(),
        approval_revision: 3,
        approval_allowed: true,
        approval_revocation_epoch: 1,
        profile_digest: profile.profile_digest(),
        pricing_revision_digest: profile.pricing_revision_digest(),
        activation_binding_kind: ProviderLeaseBindingKind::ProtectedV2,
        activation_binding_digest: [4; 32],
        token_budget_limit: 10_000,
        cost_budget_limit_micros: 1_000_000,
        authority_ttl_seconds: 120,
        lease_ttl_seconds: 600,
    }
}

fn authority_issue_request(
    prepared: &PreparedRequest,
    profile: &OpenAiResponsesTextProfile,
) -> ProviderAuthorityIssueRequest {
    ProviderAuthorityIssueRequest {
        principal_id: "principal-1".into(),
        conversation_id: ConversationId::from_bytes([6; 16]),
        taskrun_id: TaskRunId::from_bytes([7; 16]),
        execution_attempt_id: AttemptId::from_bytes([8; 16]),
        prepared: gocode_provider::PreparedProviderRecord {
            call_id: prepared.call().call_id(),
            call_digest_version: prepared.request_ref().digest_version(),
            prepared_digest: *prepared.request_ref().as_bytes(),
            render_digest: *prepared.render_digest(),
            profile_digest: profile.profile_digest(),
        },
        pricing_revision_digest: profile.pricing_revision_digest(),
        requested_input_tokens: 512,
        requested_output_tokens: 1_024,
        max_cost_micros: 50_000,
        currency: "USD".into(),
        provider_idempotency_key: "h2-nack-one-effect".into(),
    }
}
