use runne_application::provider::ProviderLeaseBindingKind;
use runne_store::provider::{
    ProviderRuntimeAuthorityConfig, ProviderRuntimeLaunchCapability, SqliteProviderDispatchStore,
};

use crate::validated_reopen::ProviderTestDatabase;

pub(super) fn fresh_store(
    name: &str,
) -> (
    ProviderTestDatabase,
    SqliteProviderDispatchStore,
    ProviderRuntimeLaunchCapability,
) {
    let database = ProviderTestDatabase::new(name);
    let execution = database.execution();
    let launch = execution.activate_runtime_launch(&config()).unwrap();
    crate::online_proof::arm(&execution, 1);
    let dispatch = database.dispatch();
    (database, dispatch, launch)
}

pub(super) fn config() -> ProviderRuntimeAuthorityConfig {
    ProviderRuntimeAuthorityConfig {
        runtime_authority_id: [1; 16],
        database_generation: 1,
        principal_id: "provider-dispatch-test-principal".to_owned(),
        owner_id: "provider-dispatch-test-runtime".to_owned(),
        scope: "provider.dispatch".to_owned(),
        generation: 1,
        fencing_token: 9,
        capability_grant_id: "provider-dispatch-test-grant".to_owned(),
        capability_revision: 1,
        capability_allowed: true,
        capability_revocation_epoch: 1,
        approval_id: "provider-dispatch-test-approval".to_owned(),
        approval_revision: 1,
        approval_allowed: true,
        approval_revocation_epoch: 1,
        profile_digest: [4; 32],
        pricing_revision_digest: [22; 32],
        activation_binding_kind: ProviderLeaseBindingKind::ProtectedV2,
        activation_binding_digest: [23; 32],
        token_budget_limit: 10_000,
        cost_budget_limit_micros: 1_000_000,
        authority_ttl_seconds: 120,
        lease_ttl_seconds: 600,
    }
}

pub(super) fn stream_dispatch(
    database: &ProviderTestDatabase,
    call_byte: u8,
) -> runne_provider::ProviderDispatchClaim {
    use runne_application::provider::ProviderAuthorityIssueRequest;
    use runne_domain::id::{AttemptId, ConversationId, TaskRunId};
    use runne_provider::{
        ModelRef, PreparedRequest, ProviderCall, ProviderCallId, ProviderId, ProviderStreamId,
    };
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([call_byte; 16]),
        ModelRef::new(
            ProviderId::new("fixture-provider").unwrap(),
            "fixture-model",
            "2026-09-04",
        )
        .unwrap(),
        [5; 32],
        1,
        serde_json::Value::Null,
    )
    .unwrap();
    let prepared = PreparedRequest::from_call(&call).unwrap();
    let execution = database.execution();
    let launch = execution.activate_runtime_launch(&config()).unwrap();
    crate::online_proof::arm(&execution, 1);
    let request = ProviderAuthorityIssueRequest {
        provider_id: call.model_ref().provider_id().clone(),
        principal_id: "provider-dispatch-test-principal".into(),
        conversation_id: ConversationId::from_bytes([call_byte.wrapping_add(30); 16]),
        taskrun_id: TaskRunId::from_bytes([call_byte.wrapping_add(40); 16]),
        execution_attempt_id: AttemptId::from_bytes([call_byte.wrapping_add(50); 16]),
        prepared: runne_provider::PreparedProviderRecord {
            call_id: call.call_id(),
            call_digest_version: prepared.request_ref().digest_version(),
            prepared_digest: *prepared.request_ref().as_bytes(),
            render_digest: *prepared.render_digest(),
            profile_digest: [4; 32],
        },
        pricing_revision_digest: [22; 32],
        requested_input_tokens: 1,
        requested_output_tokens: 1,
        max_cost_micros: 1,
        currency: "USD".into(),
        provider_idempotency_key: format!("provider-dispatch-test-{call_byte}"),
    };
    crate::online_stream_fixture::start(
        database,
        &execution,
        &launch,
        call,
        &request,
        ProviderStreamId::from_bytes([10; 16]),
        call_byte,
    )
    .1
}
