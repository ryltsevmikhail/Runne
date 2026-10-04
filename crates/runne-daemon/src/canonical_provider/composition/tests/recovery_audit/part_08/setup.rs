use super::super::fixture::*;
use crate::canonical_provider::composition::DaemonCanonicalProviderService;
use crate::canonical_provider::composition::tests::{command_context, online_dispatch};
use runne_api::CreateConversationInput;
use runne_application::commands::{
    BeginClaimedConversationTextInput, BeginConversationTextInput, SubmitTaskRunInput,
};
use runne_application::conversation_service::ConversationService;
use runne_application::ports::{
    BindPreparedTaskRunProviderEffect, ExecutionNodeId, PreparedTaskRunProviderRequest,
    RuntimeAuthorityId, TaskRunAssignmentIdentity, TaskRunClaimResult, TaskRunProviderBindingPort,
};
use runne_application::provider::ProviderAuthorityIssueRequest;
use runne_application::service::{ClaimTaskRunInput, TaskRunService};
use runne_domain::id::TaskRunId;
use runne_domain::message::MessageText;
use runne_domain::task_run::{SelectedProviderProfile, TaskRunInput};
use runne_provider::{
    ModelRef, PreparedProviderRecord as ContractPreparedProviderRecord, ProviderCall,
    ProviderCallId, ProviderDispatchClaim, ProviderId, TextProviderProfile,
};
use runne_store::provider::PreparedProviderRecord;
pub(in crate::canonical_provider::composition::tests) struct SavedRemoteDispatch {
    pub(in crate::canonical_provider::composition::tests) taskrun_id: TaskRunId,
    pub(in crate::canonical_provider::composition::tests) attempt_id: runne_domain::id::AttemptId,
    pub(in crate::canonical_provider::composition::tests) claim: ProviderDispatchClaim,
    pub(in crate::canonical_provider::composition::tests) rendered_request: Vec<u8>,
}

pub(in crate::canonical_provider::composition::tests) fn prepare(
    harness: &Harness,
    service: &DaemonCanonicalProviderService,
    route: &crate::canonical_provider::execution::SecondaryProfileRoute,
) -> SavedRemoteDispatch {
    prepare_with_instance(harness, service, route, 0)
}

pub(in crate::canonical_provider::composition::tests) fn prepare_with_instance(
    harness: &Harness,
    service: &DaemonCanonicalProviderService,
    route: &crate::canonical_provider::execution::SecondaryProfileRoute,
    instance: u16,
) -> SavedRemoteDispatch {
    let authority = RuntimeAuthorityId(hex::encode(service.runtime_authority_id));
    let offset = instance
        .checked_mul(16)
        .expect("fixture instance is bounded");
    let id = |value: u16| format!("018f2e3a-7000-7000-8000-{value:012x}");
    let conversation_id = id(0x186 + offset).parse().unwrap();
    let workspace_id = "018f2e3a-7000-7000-8000-000000000093".parse().unwrap();
    ConversationService::new(
        harness.store.clone(),
        harness.store.clone(),
        authority.clone(),
    )
    .create_from_application(
        &command_context(&id(0x187 + offset), &format!("secondary-create-{instance}")),
        CreateConversationInput {
            conversation_id,
            workspace_id,
            command_id: id(0x187 + offset).parse().unwrap(),
            idempotency_key: runne_domain::id::IdempotencyKey::new(format!(
                "secondary-create-{instance}"
            ))
            .unwrap(),
            scope: runne_api::ConversationContextScope::Workspace,
        },
    )
    .unwrap();
    let taskruns = TaskRunService::new(
        harness.store.clone(),
        harness.store.clone(),
        harness.store.clone(),
        authority.clone(),
    );
    let submitted = taskruns
        .submit_task_run(
            &command_context(&id(0x188 + offset), &format!("secondary-submit-{instance}")),
            SubmitTaskRunInput {
                conversation_id,
                workspace_id,
                input: TaskRunInput::new("recovery fixture".into())
                    .unwrap()
                    .with_selected_profile(
                        SelectedProviderProfile::new(
                            route.profile.profile_id().to_owned(),
                            route.profile.profile_digest(),
                        )
                        .unwrap(),
                    )
                    .unwrap(),
            },
        )
        .unwrap();
    let runne_application::commands::CommandOutcome::TaskRunSubmitted { taskrun_id, .. } =
        submitted
    else {
        panic!("public TaskRun submit did not return a task run");
    };
    let node = service.runtime_authority_id;
    runne_store::execution_node::register_local_linux_node(
        &harness.writer_connection(),
        node,
        harness.generation(),
        runne_store::execution_node::LinuxNodeDescriptor { capacity: 2 },
        300,
    )
    .unwrap();
    let claim = taskruns
        .claim_task_run(
            &command_context(&id(0x189 + offset), &format!("secondary-claim-{instance}")),
            ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id: ExecutionNodeId(uuid::Uuid::from_bytes(node).to_string()),
                node_epoch: harness.generation(),
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 300_000,
            },
            &harness.store,
        )
        .unwrap();
    let TaskRunClaimResult::Committed(claim) = claim else {
        panic!("public TaskRun claim did not commit");
    };
    let identity = TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id: claim.attempt_id,
        node_id: claim.node_id.clone(),
        node_epoch: claim.node_epoch,
        fence: claim.fence,
    };
    let text = harness.text_service();
    text.begin_claimed_text(
        &command_context(&id(0x190 + offset), &format!("secondary-begin-{instance}")),
        BeginClaimedConversationTextInput {
            original: BeginConversationTextInput {
                conversation_id,
                expected_version: 1,
                text: MessageText::new("recovery fixture").unwrap(),
            },
            taskrun_id,
            attempt_id: claim.attempt_id,
            taskrun_version: claim.new_version,
            workspace_id,
            assignment: identity.clone(),
        },
    )
    .unwrap();
    let provider = ProviderId::new(route.provider_id.as_ref()).unwrap();
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([u8::try_from(191 + offset / 16).unwrap(); 16]),
        ModelRef::new(
            provider.clone(),
            route.model_id.to_string(),
            route.model_revision.to_string(),
        )
        .unwrap(),
        [192; 32],
        1024,
        serde_json::json!({"input":"recovery fixture"}),
    )
    .unwrap();
    let prepared = route.adapter.prepare(&call).unwrap();
    let record = PreparedProviderRecord {
        call_id: call.call_id(),
        call_digest_version: prepared.request_ref().digest_version(),
        prepared_digest: *prepared.request_ref().as_bytes(),
        render_digest: *prepared.render_digest(),
        profile_digest: route.profile.profile_digest(),
    };
    service
        .dispatch_store
        .persist_prepared(&service.launch_capability, &record)
        .unwrap();
    let request = ProviderAuthorityIssueRequest {
        provider_id: provider,
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
        pricing_revision_digest: route.profile.pricing_revision_digest(),
        requested_input_tokens: 512,
        requested_output_tokens: 1024,
        max_cost_micros: 50_000,
        currency: "USD".into(),
        provider_idempotency_key: format!("saved-bg-response-fixture-{instance}"),
    };
    let provider_claim = online_dispatch::start_with_adapter(
        service,
        harness.writer_connection(),
        call,
        &request,
        None,
        route.grant.as_ref(),
        route.adapter.as_ref(),
    );
    harness
        .store
        .bind_prepared_taskrun_provider_effect(BindPreparedTaskRunProviderEffect {
            identity,
            expected_claim_version: claim.new_version,
            prepared: PreparedTaskRunProviderRequest {
                call_id: record.call_id,
                call_digest_version: record.call_digest_version,
                prepared_digest: record.prepared_digest,
                render_digest: record.render_digest,
                profile_digest: record.profile_digest,
                provider_idempotency_key: request.provider_idempotency_key,
            },
        })
        .unwrap();
    SavedRemoteDispatch {
        taskrun_id,
        attempt_id: claim.attempt_id,
        claim: provider_claim,
        rendered_request: prepared.rendered_bytes().to_vec(),
    }
}
