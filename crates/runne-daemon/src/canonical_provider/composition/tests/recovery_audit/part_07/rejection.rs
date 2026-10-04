use super::*;
use crate::canonical_provider::composition::DaemonCanonicalProviderService;
use crate::canonical_provider::composition::tests::command_context;
use runne_application::commands::{
    BeginClaimedConversationTextInput, BeginConversationTextInput, CommandOutcome,
    SubmitTaskRunInput,
};
use runne_application::ports::{
    ApplicationCommandContext, ConversationRepository, ExecutionNodeId, RuntimeAuthorityId,
    TaskRunAssignmentIdentity, TaskRunClaimResult,
};
use runne_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ContentGuardError, ProhibitedContentPort,
};
use runne_application::provider::ProviderCoordinatorRequest;
use runne_application::service::{ClaimTaskRunInput, TaskRunService};
use runne_domain::message::MessageText;
use runne_domain::task_run::{SelectedProviderProfile, TaskRunInput};
use runne_provider::{
    ModelRef, ProviderCall, ProviderCallId, ProviderCapability, ProviderId, ProviderInputRole,
    ProviderTerminalDisposition, ProviderTextInput, TextProviderProfile,
};
use runne_store::provider::{
    CredentialDispatchAuthority, ProviderCoordinatorOutcome, SqliteProviderDispatchCoordinator,
};
use std::sync::{Arc, Mutex};

#[path = "rejection_effect.rs"]
mod rejection_effect;
use rejection_effect::{RejectingEffect, StageCancellation};

pub(super) struct RejectedRun {
    pub(super) taskrun_id: runne_domain::id::TaskRunId,
    pub(super) claim_version: u64,
    pub(super) assignment: TaskRunAssignmentIdentity,
    pub(super) workspace_id: runne_domain::id::WorkspaceId,
    pub(super) cancelled_before_rejection: Option<u64>,
    pub(super) begin_context: ApplicationCommandContext,
}

struct AllowAll;
impl ProhibitedContentPort for AllowAll {
    fn inspect(
        &self,
        _: CanonicalContentBoundary,
        _: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(ContentDisposition::Allowed { policy_epoch: 1 })
    }
}

pub(super) async fn dispatch_rejected_generation(
    harness: &Harness,
    service: &Arc<DaemonCanonicalProviderService>,
    conversation_id: runne_domain::id::ConversationId,
    workspace_id: runne_domain::id::WorkspaceId,
    bind_before_reject: bool,
    cancel_before_rejection: bool,
) -> RejectedRun {
    let context = command_context("018f2e3a-7000-7000-8000-000000000120", "rejection-submit");
    let tasks = TaskRunService::new(
        harness.store.clone(),
        harness.store.clone(),
        harness.store.clone(),
        RuntimeAuthorityId(hex::encode(service.runtime_authority_id)),
    );
    let submitted = tasks
        .submit_task_run(
            &context,
            SubmitTaskRunInput {
                conversation_id,
                workspace_id,
                input: TaskRunInput::new("rejected prompt".into())
                    .unwrap()
                    .with_selected_profile(
                        SelectedProviderProfile::new(
                            service.profile.profile_id().to_owned(),
                            service.profile.profile_digest(),
                        )
                        .unwrap(),
                    )
                    .unwrap(),
            },
        )
        .unwrap();
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = submitted else {
        panic!("submit did not create TaskRun")
    };
    let claim_context = command_context("018f2e3a-7000-7000-8000-000000000121", "rejection-claim");
    let claim = tasks
        .claim_task_run(
            &claim_context,
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
        panic!("claim did not commit")
    };
    let assignment = TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id: claim.attempt_id,
        node_id: claim.node_id.clone(),
        node_epoch: claim.node_epoch,
        fence: claim.fence,
    };
    let actor_context = command_context("018f2e3a-7000-7000-8000-000000000122", "rejection-begin");
    let conversation = harness.store.load_conversation(conversation_id).unwrap();
    let original = BeginConversationTextInput {
        conversation_id,
        expected_version: conversation.current_version,
        text: MessageText::new("rejected prompt").unwrap(),
    };
    let text_service = service.conversation_service.clone();
    let assignment_for_effect = assignment.clone();
    let _started = text_service
        .begin_claimed_text(
            &actor_context,
            BeginClaimedConversationTextInput {
                original,
                taskrun_id,
                attempt_id: claim.attempt_id,
                taskrun_version: claim.new_version,
                workspace_id,
                assignment,
            },
        )
        .unwrap();
    let cancellation_result = Arc::new(Mutex::new(None));
    let cancellation = cancel_before_rejection.then(|| StageCancellation {
        taskrun_id,
        expected_version: claim.new_version,
        context: command_context("018f2e3a-7000-7000-8000-000000000125", "stage-cancel"),
        authority: RuntimeAuthorityId(hex::encode(service.runtime_authority_id)),
        result: Arc::clone(&cancellation_result),
    });
    let call = ProviderCall::new(
        ProviderCallId::from_bytes([81; 16]),
        ModelRef::new(
            ProviderId::new(service.provider_id.as_ref()).unwrap(),
            service.model_id.as_ref(),
            service.model_revision.as_ref(),
        )
        .unwrap(),
        [82; 32],
        32,
        service.profile.call_binding_extension(),
    )
    .unwrap()
    .with_text_inputs(vec![
        ProviderTextInput::new(ProviderInputRole::User, "rejected prompt").unwrap(),
    ])
    .unwrap()
    .with_required_capabilities(vec![ProviderCapability::Streaming]);
    let provider = FailureProvider {
        disposition: ProviderTerminalDisposition::RemoteFailed,
    };
    let effect = RejectingEffect {
        store: harness.store.clone(),
        binding: bind_before_reject.then_some((
            assignment_for_effect,
            claim.new_version,
            service.profile.profile_digest(),
        )),
        cancellation,
    };
    let guard = AllowAll;
    let requested_output_tokens = call.max_output_tokens();
    let coordinator = SqliteProviderDispatchCoordinator::new(
        service.dispatch_store.as_ref(),
        service.execution_store.as_ref(),
        CredentialDispatchAuthority::new(
            service.credential_store.as_ref(),
            &service.launch_capability,
        ),
        &provider,
        &effect,
        &guard,
    );
    #[cfg(all(test, feature = "test-support"))]
    let schema_probe = harness.query_connection();
    let outcome = coordinator
        .dispatch(ProviderCoordinatorRequest {
            call,
            principal_id: actor_context.principal_id.0.clone(),
            conversation_id,
            taskrun_id,
            execution_attempt_id: claim.attempt_id,
            profile_digest: service.profile.profile_digest(),
            pricing_revision_digest: service.profile.pricing_revision_digest(),
            requested_input_tokens: 512,
            requested_output_tokens,
            max_cost_micros: 50_000,
            currency: "USD".into(),
            provider_idempotency_key: "rejected-before-effect".into(),
        })
        .await
        .unwrap();
    #[cfg(all(test, feature = "test-support"))]
    {
        let diagnosis = runne_store::schema::diagnose_schema_matchers(&schema_probe);
        if diagnosis != runne_store::schema::SchemaMatcherDiagnosis::Accepted {
            eprintln!("provider_schema_matcher_diagnosis={diagnosis:?}");
        }
    }
    assert!(matches!(
        outcome,
        ProviderCoordinatorOutcome::RejectedBeforeEffect { .. }
    ));
    let cancelled_before_rejection = cancellation_result.lock().unwrap().take();
    assert_eq!(
        cancelled_before_rejection.is_some(),
        cancel_before_rejection,
        "cancellation must be committed from the actual provider stage before its rejection"
    );
    assert!(
        harness
            .store
            .provider_rejection_recovery_candidates(None, 128)
            .unwrap()
            .candidates
            .iter()
            .any(|candidate| candidate.taskrun_id == taskrun_id)
    );
    let binding_count: i64 = harness
        .query_connection()
        .query_row(
            "SELECT COUNT(*) FROM taskrun_provider_bindings WHERE taskrun_id=?1",
            [taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(binding_count, i64::from(bind_before_reject));
    let claim_version = claim.new_version;
    drop(tasks);
    RejectedRun {
        taskrun_id,
        claim_version,
        assignment: TaskRunAssignmentIdentity {
            taskrun_id,
            attempt_id: claim.attempt_id,
            node_id: claim.node_id,
            node_epoch: claim.node_epoch,
            fence: claim.fence,
        },
        workspace_id,
        cancelled_before_rejection,
        begin_context: actor_context,
    }
}
