use super::*;
use crate::canonical_provider::composition::DaemonCanonicalProviderService;
use crate::canonical_provider::composition::tests::command_context;
use crate::canonical_provider::composition::tests::online_dispatch;
use runne_api::CreateConversationInput;
use runne_application::commands::{
    BeginClaimedConversationTextInput, BeginConversationTextInput, SubmitTaskRunInput,
};
use runne_application::conversation_service::ConversationService;
use runne_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
use runne_application::ports::{
    ApplicationCommandContext, BindPreparedTaskRunProviderEffect, ExecutionNodeId,
    PreparedTaskRunProviderRequest, RuntimeAuthorityId, TaskRunAssignmentIdentity,
    TaskRunClaimReceipt, TaskRunClaimResult, TaskRunProviderBindingPort,
};
use runne_application::provider::ProviderAuthorityIssueRequest;
use runne_application::service::{ClaimTaskRunInput, TaskRunService};
use runne_domain::id::{ConversationId, TaskRunId, WorkspaceId};
use runne_domain::message::MessageText;
use runne_domain::task_run::TaskRunInput;
use runne_provider::{
    ModelRef, PreparedProviderRecord as ContractPreparedProviderRecord, ProviderCall,
    ProviderCallId, ProviderCapability, ProviderDispatchClaim, ProviderId, ProviderInputRole,
    ProviderStreamId, ProviderTextInput, TextProviderProfile,
};
use runne_store::provider::PreparedProviderRecord;
use std::sync::Arc;

pub(super) struct PreparedFailureScenario {
    pub(super) harness: Harness,
    pub(super) service: Arc<DaemonCanonicalProviderService>,
    pub(super) taskrun_id: TaskRunId,
    pub(super) conversation_id: ConversationId,
    pub(super) workspace_id: WorkspaceId,
    pub(super) claim: TaskRunClaimReceipt,
    pub(super) begin_context: ApplicationCommandContext,
    pub(super) provider_claim: ProviderDispatchClaim,
    pub(super) record: PreparedProviderRecord,
    pub(super) stream: ProviderStreamId,
}

pub(super) async fn prepare_failure_scenario() -> PreparedFailureScenario {
    prepare_failure_scenario_with_profile().await
}

pub(super) async fn prepare_unknown_failure_scenario() -> PreparedFailureScenario {
    prepare_failure_scenario_with_profile().await
}

async fn prepare_failure_scenario_with_profile() -> PreparedFailureScenario {
    let (harness, service) = Harness::new_openai_provider().await;
    harness
        .store
        .provider_rejection_recovery_candidates(None, 128)
        .unwrap();
    let conversation_id = "018f2e3a-7000-7000-8000-000000000097".parse().unwrap();
    let workspace_id = "018f2e3a-7000-7000-8000-000000000093".parse().unwrap();
    ConversationService::new(
        harness.store.clone(),
        harness.store.clone(),
        RuntimeAuthorityId(hex::encode(service.runtime_authority_id)),
    )
    .create_from_application(
        &command_context("018f2e3a-7000-7000-8000-000000000098", "failure-create"),
        CreateConversationInput {
            conversation_id,
            workspace_id,
            command_id: "018f2e3a-7000-7000-8000-000000000098".parse().unwrap(),
            idempotency_key: runne_domain::id::IdempotencyKey::new("failure-create").unwrap(),
            scope: runne_api::ConversationContextScope::Workspace,
        },
    )
    .unwrap();
    let submit_context = command_context("018f2e3a-7000-7000-8000-000000000099", "failure-submit");
    let taskruns = TaskRunService::new(
        harness.store.clone(),
        harness.store.clone(),
        harness.store.clone(),
        RuntimeAuthorityId(hex::encode(service.runtime_authority_id)),
    );
    let submitted = taskruns
        .submit_task_run(
            &submit_context,
            SubmitTaskRunInput {
                conversation_id,
                workspace_id,
                input: TaskRunInput::new("failure prompt".into()).unwrap(),
            },
        )
        .unwrap();
    let runne_application::commands::CommandOutcome::TaskRunSubmitted { taskrun_id, .. } =
        submitted
    else {
        panic!()
    };
    let node_bytes = service.runtime_authority_id;
    runne_store::execution_node::register_local_linux_node(
        &harness.writer_connection(),
        node_bytes,
        harness.generation(),
        runne_store::execution_node::LinuxNodeDescriptor { capacity: 1 },
        300,
    )
    .unwrap();
    let claim_context = command_context("018f2e3a-7000-7000-8000-000000000100", "failure-claim");
    let claim = taskruns
        .claim_task_run(
            &claim_context,
            ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id: ExecutionNodeId(uuid::Uuid::from_bytes(node_bytes).to_string()),
                node_epoch: harness.generation(),
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 300_000,
            },
            &harness.store,
        )
        .unwrap();
    let TaskRunClaimResult::Committed(claim) = claim else {
        panic!()
    };
    let identity = TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id: claim.attempt_id,
        node_id: claim.node_id.clone(),
        node_epoch: claim.node_epoch,
        fence: claim.fence,
    };
    let text: Arc<dyn ConversationTextCommandService> = Arc::new(ConversationTextService::new(
        harness.store.clone(),
        harness.store.clone(),
        RuntimeAuthorityId(hex::encode(service.runtime_authority_id)),
        harness.prohibited(),
    ));
    let begin_context = command_context("018f2e3a-7000-7000-8000-000000000101", "failure-begin");
    let original = BeginConversationTextInput {
        conversation_id,
        expected_version: 1,
        text: MessageText::new("failure prompt").unwrap(),
    };
    let _started = text
        .begin_claimed_text(
            &begin_context,
            BeginClaimedConversationTextInput {
                original: original.clone(),
                taskrun_id,
                attempt_id: claim.attempt_id,
                taskrun_version: claim.new_version,
                workspace_id,
                assignment: identity.clone(),
            },
        )
        .unwrap();
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([71; 16]),
        ModelRef::new(
            ProviderId::new(service.provider_id.as_ref()).unwrap(),
            service.model_id.as_ref(),
            service.model_revision.as_ref(),
        )
        .unwrap(),
        [72; 32],
        1_024,
        service.profile.call_binding_extension(),
    )
    .unwrap()
    .with_text_inputs(vec![
        ProviderTextInput::new(ProviderInputRole::User, "failure prompt").unwrap(),
    ])
    .unwrap()
    .with_required_capabilities(vec![ProviderCapability::Streaming]);
    let prepared = service.adapter.prepare(&call).unwrap();
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
    let key = "failure-recovery-provider-key";
    let request = ProviderAuthorityIssueRequest {
        provider_id: call.model_ref().provider_id().clone(),
        principal_id: "local-owner".into(),
        conversation_id,
        taskrun_id,
        execution_attempt_id: claim.attempt_id,
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
        provider_idempotency_key: key.into(),
    };
    let stream = ProviderStreamId::from_bytes([73; 16]);
    let provider_claim = online_dispatch::start(
        &service,
        harness.writer_connection(),
        call,
        &request,
        Some(stream),
        None,
    );
    harness
        .store
        .bind_prepared_taskrun_provider_effect(BindPreparedTaskRunProviderEffect {
            identity: identity.clone(),
            expected_claim_version: claim.new_version,
            prepared: PreparedTaskRunProviderRequest {
                call_id: record.call_id,
                call_digest_version: record.call_digest_version,
                prepared_digest: record.prepared_digest,
                render_digest: record.render_digest,
                profile_digest: record.profile_digest,
                provider_idempotency_key: key.into(),
            },
        })
        .unwrap();
    assert!(
        harness
            .store
            .provider_failure_recovery_candidates(None, 128)
            .unwrap()
            .candidates
            .is_empty()
    );
    assert!(
        harness
            .store
            .provider_rejection_recovery_candidates(None, 128)
            .unwrap()
            .candidates
            .is_empty()
    );
    PreparedFailureScenario {
        harness,
        service,
        taskrun_id,
        conversation_id,
        workspace_id,
        claim,
        begin_context,
        provider_claim,
        record,
        stream,
    }
}
