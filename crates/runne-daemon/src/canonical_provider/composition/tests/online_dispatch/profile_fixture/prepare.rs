use std::sync::{Arc, atomic::Ordering};

use runne_application::commands::{
    BeginClaimedConversationTextInput, BeginConversationTextInput, SubmitTaskRunInput,
};
use runne_application::conversation_service::ConversationService;
use runne_application::ports::{
    BindPreparedTaskRunProviderEffect, EventStore, ExecutionNodeId, PreparedTaskRunProviderRequest,
    TaskRunAssignmentIdentity, TaskRunClaimResult, TaskRunProviderBindingPort,
};
use runne_application::provider::ProviderAuthorityIssueRequest;
use runne_application::service::{ClaimTaskRunInput, TaskRunService};
use runne_domain::id::{CommandId, IdempotencyKey};
use runne_domain::message::MessageText;
use runne_domain::task_run::{SelectedProviderProfile, TaskRunInput};
use runne_provider::{ProviderId, TextProviderProfile};
use runne_store::provider::PreparedProviderRecord;

use super::super::super::recovery_audit::Harness;
use super::super::DaemonCanonicalProviderService;
use super::{PrimaryProfileFixture, SenderFixture};
use crate::canonical_provider::CanonicalProviderEffect;

pub(in crate::canonical_provider::composition::tests) struct PreparedDispatch {
    pub(in crate::canonical_provider::composition::tests) taskrun_id: runne_domain::id::TaskRunId,
    pub(in crate::canonical_provider::composition::tests) version: u64,
    pub(in crate::canonical_provider::composition::tests) request: runne_provider::DispatchRequest,
    pub(in crate::canonical_provider::composition::tests) credential:
        runne_store::provider::CredentialDispatchBinding,
    pub(in crate::canonical_provider::composition::tests) receipt:
        runne_store::provider::ProviderEffectStartReceipt,
}

pub(in crate::canonical_provider::composition::tests) async fn prepare_primary_with_instance(
    harness: &Harness,
    service: &DaemonCanonicalProviderService,
    profile: &PrimaryProfileFixture,
    effect: &dyn CanonicalProviderEffect,
    instance: u16,
) -> PreparedDispatch {
    let suffix = u64::from(instance) * 16;
    let id = |value: u64| format!("018f2e3a-7000-7000-8000-{value:012x}");
    let authority = harness.authority();
    let workspace_id = "018f2e3a-7000-7000-8000-000000000093".parse().unwrap();
    let conversation_id = id(0x300 + suffix).parse().unwrap();
    ConversationService::new(
        harness.store.clone(),
        harness.store.clone(),
        authority.clone(),
    )
    .create_from_application(
        &crate::canonical_provider::composition::tests::command_context(
            &id(0x301 + suffix),
            &format!("primary-create-{instance}"),
        ),
        runne_api::CreateConversationInput {
            conversation_id,
            workspace_id,
            command_id: id(0x301 + suffix).parse::<CommandId>().unwrap(),
            idempotency_key: IdempotencyKey::new(format!("primary-create-{instance}")).unwrap(),
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
    let selected = SelectedProviderProfile::new(
        profile.profile.profile_id().to_owned(),
        profile.profile.profile_digest(),
    )
    .unwrap();
    let submitted = taskruns
        .submit_task_run(
            &crate::canonical_provider::composition::tests::command_context(
                &id(0x302 + suffix),
                &format!("primary-submit-{instance}"),
            ),
            SubmitTaskRunInput {
                conversation_id,
                workspace_id,
                input: TaskRunInput::new("primary final-send fixture".into())
                    .unwrap()
                    .with_selected_profile(selected)
                    .unwrap(),
            },
        )
        .unwrap();
    let runne_application::commands::CommandOutcome::TaskRunSubmitted { taskrun_id, .. } =
        submitted
    else {
        panic!("public TaskRun submit did not return a task run");
    };
    runne_store::execution_node::register_local_linux_node(
        &harness.writer_connection(),
        service.runtime_authority_id,
        harness.generation(),
        runne_store::execution_node::LinuxNodeDescriptor { capacity: 2 },
        300,
    )
    .unwrap();
    let claim = taskruns
        .claim_task_run(
            &crate::canonical_provider::composition::tests::command_context(
                &id(0x303 + suffix),
                &format!("primary-claim-{instance}"),
            ),
            ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id: ExecutionNodeId(
                    uuid::Uuid::from_bytes(service.runtime_authority_id).to_string(),
                ),
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
    let assignment = TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id: claim.attempt_id,
        node_id: claim.node_id.clone(),
        node_epoch: claim.node_epoch,
        fence: claim.fence,
    };
    harness
        .text_service()
        .begin_claimed_text(
            &crate::canonical_provider::composition::tests::command_context(
                &id(0x304 + suffix),
                &format!("primary-begin-{instance}"),
            ),
            BeginClaimedConversationTextInput {
                original: BeginConversationTextInput {
                    conversation_id,
                    expected_version: 1,
                    text: MessageText::new("primary final-send fixture").unwrap(),
                },
                taskrun_id,
                attempt_id: claim.attempt_id,
                taskrun_version: claim.new_version,
                workspace_id,
                assignment,
            },
        )
        .unwrap();
    let prepared = effect.prepare(&profile.call).unwrap();
    let record = PreparedProviderRecord {
        call_id: profile.call.call_id(),
        call_digest_version: prepared.request_ref().digest_version(),
        prepared_digest: *prepared.request_ref().as_bytes(),
        render_digest: *prepared.render_digest(),
        profile_digest: profile.profile.profile_digest(),
    };
    service
        .dispatch_store
        .persist_prepared(&service.launch_capability, &record)
        .unwrap();
    let request = ProviderAuthorityIssueRequest {
        provider_id: ProviderId::new(profile.provider_id.as_str()).unwrap(),
        principal_id: "local-owner".into(),
        conversation_id,
        taskrun_id,
        execution_attempt_id: claim.attempt_id,
        prepared: runne_provider::PreparedProviderRecord {
            call_id: record.call_id,
            call_digest_version: record.call_digest_version,
            prepared_digest: record.prepared_digest,
            render_digest: record.render_digest,
            profile_digest: record.profile_digest,
        },
        pricing_revision_digest: profile.profile.pricing_revision_digest(),
        requested_input_tokens: 16,
        requested_output_tokens: u64::from(profile.call.max_output_tokens()),
        max_cost_micros: 100_000,
        currency: profile.profile.currency().to_owned(),
        provider_idempotency_key: format!("primary-final-send-{instance}"),
    };
    let (provider_claim, credential, receipt) = super::super::start_with_receipt(
        service,
        harness.writer_connection(),
        profile.call.clone(),
        &request,
    )
    .await;
    let assignment = TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id: claim.attempt_id,
        node_id: claim.node_id,
        node_epoch: claim.node_epoch,
        fence: claim.fence,
    };
    harness
        .store
        .bind_prepared_taskrun_provider_effect(BindPreparedTaskRunProviderEffect {
            identity: assignment,
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
    let dispatch = runne_provider::DispatchRequest::new(prepared, provider_claim).unwrap();
    let version = harness
        .store
        .load_task_run(taskrun_id)
        .unwrap()
        .current_version;
    PreparedDispatch {
        taskrun_id,
        version,
        request: dispatch,
        credential,
        receipt,
    }
}

pub(in crate::canonical_provider::composition::tests) async fn assert_cancel_before_send(
    fixture: SenderFixture,
) {
    let (harness, service) =
        super::build_service(&fixture.profile, Arc::clone(&fixture.effect)).await;
    let prepared = prepare_primary_with_instance(
        &harness,
        &service,
        &fixture.profile,
        fixture.effect.as_ref(),
        0,
    )
    .await;
    let ready = fixture
        .effect
        .stage_effect(prepared.request, prepared.credential)
        .await
        .expect("actual adapter stages the authorized dispatch");
    let effect = Arc::clone(&fixture.effect);
    let barrier = Arc::clone(&fixture.barrier);
    let mut task =
        tokio::spawn(async move { effect.dispatch_effect(ready, prepared.receipt).await });
    let entered = barrier.entered.notified();
    tokio::pin!(entered);
    {
        let barrier_timeout = tokio::time::timeout(std::time::Duration::from_secs(5), &mut entered);
        let task_timeout = tokio::time::timeout(std::time::Duration::from_secs(5), &mut task);
        tokio::pin!(barrier_timeout);
        tokio::pin!(task_timeout);
        tokio::select! {
            result = &mut barrier_timeout => result.expect("real adapter transport pre-consume barrier"),
            result = &mut task_timeout => panic!("actual adapter returned before transport barrier: {result:?}"),
        }
    }
    TaskRunService::new(
        harness.store.clone(),
        harness.store.clone(),
        harness.store.clone(),
        harness.authority(),
    )
    .cancel_task_run(
        &crate::canonical_provider::composition::tests::command_context(
            "018f2e3a-7000-7000-8000-0000000003ff",
            "primary-final-send-cancel",
        ),
        runne_application::commands::CancelTaskRunInput {
            taskrun_id: prepared.taskrun_id,
            expected_version: prepared.version,
        },
    )
    .unwrap();
    fixture.barrier.release();
    assert!(task.await.unwrap().is_err());
    assert_eq!(fixture.barrier.transport_entries.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.barrier.posts.load(Ordering::SeqCst), 0);
    if fixture.materializer_expected {
        super::assert_materializer_called(&fixture.materializer);
    }
}
