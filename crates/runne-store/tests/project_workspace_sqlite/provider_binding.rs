use super::claim::node_registration;
use super::support::*;
use runne_application::commands::SubmitTaskRunInput;
use runne_application::commands::{
    BeginClaimedConversationTextInput, BeginConversationTextInput, CancelTaskRunInput,
    CommandOutcome,
};
use runne_application::conversation_service::ConversationService;
use runne_application::conversation_text_service::ConversationTextCommandService;
use runne_application::conversation_text_service::ConversationTextService;
use runne_application::ports::{
    BindPreparedTaskRunProviderEffect, ExecutionNodeId, PreparedTaskRunProviderRequest,
    RuntimeAuthorityId, TaskRunAssignmentIdentity, TaskRunAssignmentPort, TaskRunClaimResult,
    TaskRunProviderBindingPort, TaskRunProviderBindingResult,
};
use runne_application::provider::ProviderAuthorityIssueRequest;
use runne_application::service::ClaimTaskRunInput;
use runne_application::service::TaskRunService;
use runne_domain::id::{AttemptId, ConversationId, WorkspaceId};
use runne_domain::message::MessageText;
use runne_provider::{
    ModelRef, PreparedProviderRecord as ContractPreparedProviderRecord, PreparedRequest,
    ProviderCall, ProviderCallId, ProviderId,
};
use runne_store::provider::{
    PreparedProviderRecord, ProviderAuthorityIssueOutcome, ProviderRuntimeAuthorityConfig,
};
use std::sync::Arc;

fn provider_config() -> ProviderRuntimeAuthorityConfig {
    ProviderRuntimeAuthorityConfig {
        runtime_authority_id: [1; 16],
        database_generation: 7,
        principal_id: "owner".into(),
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
    }
}

fn provider_request(
    taskrun_id: runne_domain::id::TaskRunId,
    attempt_id: AttemptId,
    conversation_id: ConversationId,
) -> (
    PreparedProviderRecord,
    ContractPreparedProviderRecord,
    ProviderAuthorityIssueRequest,
) {
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([0x44; 16]),
        ModelRef::new(
            ProviderId::new("fixture-provider").unwrap(),
            "fixture-model",
            "2026-07-31",
        )
        .unwrap(),
        [0x45; 32],
        1_024,
        serde_json::Value::Null,
    )
    .unwrap();
    let prepared_call = PreparedRequest::from_call(&call).unwrap();
    let record = PreparedProviderRecord {
        call_id: call.call_id(),
        call_digest_version: prepared_call.request_ref().digest_version(),
        prepared_digest: *prepared_call.request_ref().as_bytes(),
        render_digest: *prepared_call.render_digest(),
        profile_digest: [2; 32],
    };
    let contract = ContractPreparedProviderRecord {
        call_id: record.call_id,
        call_digest_version: record.call_digest_version,
        prepared_digest: record.prepared_digest,
        render_digest: record.render_digest,
        profile_digest: record.profile_digest,
    };
    let issue = ProviderAuthorityIssueRequest {
        provider_id: ProviderId::new("fixture-provider").unwrap(),
        principal_id: "owner".into(),
        conversation_id,
        taskrun_id,
        execution_attempt_id: attempt_id,
        prepared: contract,
        pricing_revision_digest: [3; 32],
        requested_input_tokens: 512,
        requested_output_tokens: 1_024,
        max_cost_micros: 50_000,
        currency: "USD".into(),
        provider_idempotency_key: "taskrun-provider-binding".into(),
    };
    (record, contract, issue)
}

struct Fixture {
    database: Database,
    identity: TaskRunAssignmentIdentity,
    prepared: PreparedTaskRunProviderRequest,
}

fn fixture(name: &str) -> Fixture {
    let runtime_authority = RuntimeAuthorityId("01010101010101010101010101010101".into());
    let database = Database::new_with_database_authority(name, runtime_authority.clone(), [1; 16]);
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let conversation_id = ConversationId::from_bytes(command(0x57).into_bytes());
    ConversationService::new(
        database.store.clone(),
        database.store.clone(),
        runtime_authority.clone(),
    )
    .create_from_application(
        &task_context(0x67, "provider-binding-conversation"),
        runne_api::CreateConversationInput {
            conversation_id,
            workspace_id: WorkspaceId::from_bytes(WORKSPACE),
            command_id: command(0x67),
            idempotency_key: key("provider-binding-conversation"),
            scope: runne_api::ConversationContextScope::Workspace,
        },
    )
    .unwrap();
    let task_runs = TaskRunService::new(
        database.store.clone(),
        database.store.clone(),
        database.store.clone(),
        runtime_authority.clone(),
    );
    let outcome = task_runs
        .submit_task_run(
            &task_context(0x47, "provider-binding-taskrun"),
            SubmitTaskRunInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                input: runne_domain::task_run::TaskRunInput::new("test prompt".into()).unwrap(),
            },
        )
        .unwrap();
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = outcome else {
        panic!("TaskRun expected")
    };
    let (node_id, node_epoch) = node_registration(&database);
    let TaskRunClaimResult::Committed(receipt) = task_runs
        .claim_task_run(
            &task_context(0x48, "provider-binding-claim"),
            ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id: ExecutionNodeId(node_id.clone()),
                node_epoch,
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 30_000,
            },
            &database.store,
        )
        .unwrap()
    else {
        panic!("claim expected")
    };
    let identity = TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id: receipt.attempt_id,
        node_id: ExecutionNodeId(node_id),
        node_epoch,
        fence: receipt.fence,
    };
    ConversationTextService::new(
        database.store.clone(),
        database.store.clone(),
        runtime_authority,
        guard(),
    )
    .begin_claimed_text(
        &task_context(0x4b, "provider-binding-generation"),
        BeginClaimedConversationTextInput {
            original: BeginConversationTextInput {
                conversation_id,
                expected_version: 1,
                text: MessageText::new("test prompt").unwrap(),
            },
            taskrun_id,
            attempt_id: receipt.attempt_id,
            taskrun_version: receipt.new_version,
            workspace_id: WorkspaceId::from_bytes(WORKSPACE),
            assignment: identity.clone(),
        },
    )
    .unwrap();
    let dispatch =
        crate::validated_reopen::open_provider_dispatch(database.file.path(), database.identity)
            .unwrap();
    let execution =
        crate::validated_reopen::open_provider_execution(database.file.path(), database.identity)
            .unwrap();
    let launch = Arc::new(
        execution
            .activate_runtime_launch(&provider_config())
            .unwrap(),
    );
    crate::online_proof::arm(&execution, 7);
    let (stored, contract, issue) =
        provider_request(taskrun_id, receipt.attempt_id, conversation_id);
    dispatch.persist_prepared(&launch, &stored).unwrap();
    assert!(matches!(
        execution.issue(&launch, &issue).unwrap(),
        ProviderAuthorityIssueOutcome::Winner(_)
    ));
    let prepared = PreparedTaskRunProviderRequest {
        call_id: contract.call_id,
        call_digest_version: contract.call_digest_version,
        prepared_digest: contract.prepared_digest,
        render_digest: contract.render_digest,
        profile_digest: contract.profile_digest,
        provider_idempotency_key: issue.provider_idempotency_key,
    };
    Fixture {
        database,
        identity,
        prepared,
    }
}

fn bind(
    fixture: &Fixture,
    expected_claim_version: u64,
    prepared: PreparedTaskRunProviderRequest,
) -> Result<TaskRunProviderBindingResult, runne_application::ports::TaskRunProviderBindingError> {
    fixture
        .database
        .store
        .bind_prepared_taskrun_provider_effect(BindPreparedTaskRunProviderEffect {
            identity: fixture.identity.clone(),
            expected_claim_version,
            prepared,
        })
}

#[path = "provider_binding/d2_round.rs"]
mod d2_round;
mod tests;
pub(super) use d2_round::bind_d2_round_zero_for_test;
