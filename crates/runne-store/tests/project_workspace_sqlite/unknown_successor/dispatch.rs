use super::super::effect::{
    Adapter, PersistRequestThenMaybeDispatch, PersistRequestThenMaybeDispatchWithRemoteId,
};
use super::*;
use runne_application::ports::{
    BindPreparedTaskRunProviderEffect, PreparedTaskRunProviderRequest, TaskRunProviderBindingPort,
};
use runne_application::provider::ProviderCoordinatorRequest;
use runne_provider::{ModelRef, PreparedRequest, ProviderCall, ProviderCallId, ProviderId};
use runne_store::provider::{
    CredentialDispatchAuthority, PreparedProviderRecord, ProviderCoordinatorOutcome,
    ProviderEffectPort, ProviderRuntimeAuthorityConfig, SqliteProviderDispatchCoordinator,
};

pub(in super::super) fn runtime_launch(
    database: &Database,
) -> (
    Arc<runne_store::provider::SqliteProviderExecutionStore>,
    runne_store::provider::ProviderRuntimeLaunchCapability,
) {
    let execution = Arc::new(
        crate::validated_reopen::open_provider_execution(database.file.path(), database.identity)
            .unwrap(),
    );
    let config = ProviderRuntimeAuthorityConfig {
        runtime_authority_id: [1; 16],
        database_generation: 7,
        principal_id: "principal-1".into(),
        owner_id: "runtime-owner-1".into(),
        scope: "provider.dispatch".into(),
        generation: 11,
        fencing_token: 13,
        capability_grant_id: "grant-provider-network-1".into(),
        capability_revision: 2,
        capability_allowed: true,
        capability_revocation_epoch: 1,
        approval_id: "approval-provider-network-1".into(),
        approval_revision: 3,
        approval_allowed: true,
        approval_revocation_epoch: 1,
        profile_digest: [2; 32],
        pricing_revision_digest: [3; 32],
        activation_binding_kind: runne_application::provider::ProviderLeaseBindingKind::ProtectedV2,
        activation_binding_digest: [4; 32],
        token_budget_limit: 10_000,
        cost_budget_limit_micros: 1_000_000,
        authority_ttl_seconds: 120,
        lease_ttl_seconds: 600,
    };
    let launch = execution.activate_runtime_launch(&config).unwrap();
    crate::online_proof::arm_binding(
        &execution,
        runne_application::provider::ProviderJournalKeyBinding::new([9; 16], 1, [1; 16], 7)
            .unwrap(),
    );
    (execution, launch)
}

pub fn dispatch_unknown(
    database: &Database,
    credentials: &SqliteProviderCredentialLifecycleStore,
    execution: &Arc<runne_store::provider::SqliteProviderExecutionStore>,
    launch: &runne_store::provider::ProviderRuntimeLaunchCapability,
    identity: &TaskRunAssignmentIdentity,
    conversation_id: ConversationId,
) {
    dispatch_unknown_inner(
        database,
        credentials,
        execution,
        launch,
        identity,
        conversation_id,
        &PersistRequestThenMaybeDispatch(Arc::clone(execution)),
    );
}

pub fn dispatch_unknown_with_remote_id(
    database: &Database,
    credentials: &SqliteProviderCredentialLifecycleStore,
    execution: &Arc<runne_store::provider::SqliteProviderExecutionStore>,
    launch: &runne_store::provider::ProviderRuntimeLaunchCapability,
    identity: &TaskRunAssignmentIdentity,
    conversation_id: ConversationId,
    response_id: &str,
) {
    dispatch_unknown_inner(
        database,
        credentials,
        execution,
        launch,
        identity,
        conversation_id,
        &PersistRequestThenMaybeDispatchWithRemoteId {
            execution: Arc::clone(execution),
            response_id: response_id.to_owned(),
        },
    );
}

fn dispatch_unknown_inner(
    database: &Database,
    credentials: &SqliteProviderCredentialLifecycleStore,
    execution: &Arc<runne_store::provider::SqliteProviderExecutionStore>,
    launch: &runne_store::provider::ProviderRuntimeLaunchCapability,
    identity: &TaskRunAssignmentIdentity,
    conversation_id: ConversationId,
    effect: &dyn ProviderEffectPort,
) {
    let dispatch =
        crate::validated_reopen::open_provider_dispatch(database.file.path(), database.identity)
            .unwrap();
    let provider = ProviderId::new("fixture-provider").unwrap();
    let call = ProviderCall::new(
        ProviderCallId::from_bytes(*identity.taskrun_id.as_bytes()),
        ModelRef::new(provider, "fixture-model", "v1").unwrap(),
        [5; 32],
        1_024,
        serde_json::Value::Null,
    )
    .unwrap();
    let call_id = call.call_id();
    let prepared = PreparedRequest::from_call(&call).unwrap();
    dispatch
        .persist_prepared(
            launch,
            &PreparedProviderRecord {
                call_id,
                call_digest_version: prepared.request_ref().digest_version(),
                prepared_digest: *prepared.request_ref().as_bytes(),
                render_digest: *prepared.render_digest(),
                profile_digest: [2; 32],
            },
        )
        .unwrap();
    let guard = super::super::super::support::guard();
    let coordinator = SqliteProviderDispatchCoordinator::new(
        &dispatch,
        execution,
        CredentialDispatchAuthority::new(credentials, launch),
        &Adapter,
        effect,
        guard.as_ref(),
    );
    let result = futures::executor::block_on(coordinator.dispatch(ProviderCoordinatorRequest {
        call,
        principal_id: "principal-1".into(),
        conversation_id,
        taskrun_id: identity.taskrun_id,
        execution_attempt_id: identity.attempt_id,
        profile_digest: [2; 32],
        pricing_revision_digest: [3; 32],
        requested_input_tokens: 512,
        requested_output_tokens: 1_024,
        max_cost_micros: 50_000,
        currency: "USD".into(),
        provider_idempotency_key: format!("unknown-successor-effect-{}", identity.taskrun_id),
    }))
    .unwrap();
    assert_eq!(result, ProviderCoordinatorOutcome::Uncertain);
    assert_provider_bindings(database, identity);
    database
        .store
        .bind_prepared_taskrun_provider_effect(BindPreparedTaskRunProviderEffect {
            identity: identity.clone(),
            expected_claim_version: 4,
            prepared: PreparedTaskRunProviderRequest {
                call_id,
                call_digest_version: prepared.request_ref().digest_version(),
                prepared_digest: *prepared.request_ref().as_bytes(),
                render_digest: *prepared.render_digest(),
                profile_digest: [2; 32],
                provider_idempotency_key: format!(
                    "unknown-successor-effect-{}",
                    identity.taskrun_id
                ),
            },
        })
        .unwrap();
}

fn assert_provider_bindings(database: &Database, identity: &TaskRunAssignmentIdentity) {
    let connection = database.connection();
    let attempt: Vec<u8> = connection.query_row(
        "SELECT dispatch_attempt_id FROM provider_remote_request_intents WHERE taskrun_id=?1 AND taskrun_attempt_id=?2",
        rusqlite::params![identity.taskrun_id.as_bytes(), identity.attempt_id.as_bytes()],
        |row| row.get(0),
    ).unwrap();
    for (table, column) in [
        ("provider_execution_admissions", "dispatch_attempt_id"),
        ("provider_dispatch_attempts", "attempt_id"),
        (
            "provider_online_dispatch_claim_providers",
            "dispatch_attempt_id",
        ),
        (
            "provider_online_credential_effect_bindings",
            "dispatch_attempt_id",
        ),
    ] {
        let sql = format!("SELECT COUNT(*) FROM {table} WHERE {column}=?1");
        let count: i64 = connection
            .query_row(&sql, [&attempt], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1, "provider binding missing from {table}");
    }
}
