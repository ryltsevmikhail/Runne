use runne_application::conversation_text_service::ConversationTextCommandService;
use runne_application::ports::{ConversationRepository, RuntimeAuthorityId};
use runne_application::provider::ProviderRemoteRecoveryStore;
use runne_application::service::{ClaimTaskRunInput, TaskRunService};
use runne_domain::message::MessageText;
use runne_domain::task_run::{SelectedProviderProfile, TaskRunInput};
use runne_provider::{
    ProviderPricedUsage, ProviderTerminalPricing, ProviderTerminalPricingError, ProviderUsage,
};

pub(super) struct Price;
pub(super) struct UnavailablePricing;

pub(super) fn attempt(
    fixture: &super::super::super::fixture::Fixture,
) -> runne_provider::DispatchAttemptId {
    runne_provider::DispatchAttemptId::from_bytes(
        fixture
            .database
            .connection()
            .query_row(
                "SELECT dispatch_attempt_id FROM provider_remote_request_intents WHERE taskrun_id=?1",
                [fixture.taskrun_id.as_bytes().as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

pub(super) fn authority(bytes: &[u8; 16]) -> RuntimeAuthorityId {
    RuntimeAuthorityId(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub(super) fn has_assistant_output(
    fixture: &super::super::super::fixture::Fixture,
    conversation_id: runne_domain::id::ConversationId,
) -> bool {
    fixture
        .database
        .store
        .load_conversation(conversation_id)
        .unwrap()
        .events
        .iter()
        .any(|event| {
            matches!(
                event.payload(),
                runne_domain::conversation::ConversationEvent::AssistantMessageAppended {
                    taskrun_id, ..
                } if *taskrun_id == fixture.taskrun_id
            )
        })
}

pub(super) fn assert_discoverable(
    fixture: &super::super::super::fixture::Fixture,
    dispatch_attempt_id: runne_provider::DispatchAttemptId,
) {
    let page = fixture.execution.scan_remote_attempts(None, 16).unwrap();
    assert_eq!(page.attempts, vec![dispatch_attempt_id]);
    let (request, _) = fixture
        .execution
        .load_remote_identity(dispatch_attempt_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        fixture
            .execution
            .find_remote_attempt(
                request.binding.taskrun_id,
                request.binding.taskrun_attempt_id,
            )
            .unwrap(),
        Some(dispatch_attempt_id)
    );
}

pub(super) fn assert_not_discoverable(fixture: &super::super::super::fixture::Fixture) {
    assert!(
        fixture
            .execution
            .scan_remote_attempts(None, 16)
            .unwrap()
            .attempts
            .is_empty()
    );
}

pub(super) fn assert_audit_receipt_exists(
    fixture: &super::super::super::fixture::Fixture,
    dispatch_attempt_id: runne_provider::DispatchAttemptId,
) {
    let count: i64 = fixture
        .database
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM provider_remote_terminal_audit_receipts
             WHERE dispatch_attempt_id=?1",
            [dispatch_attempt_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 1, "the source has one validated audit witness");
}

impl ProviderTerminalPricing for Price {
    fn price_terminal_usage(
        &self,
        _: &[u8; 32],
        _: &[u8; 32],
        _: i64,
        _: ProviderUsage,
    ) -> Result<ProviderPricedUsage, ProviderTerminalPricingError> {
        ProviderPricedUsage::new(10, "USD".into())
    }
}

impl ProviderTerminalPricing for UnavailablePricing {
    fn price_terminal_usage(
        &self,
        _: &[u8; 32],
        _: &[u8; 32],
        _: i64,
        _: ProviderUsage,
    ) -> Result<ProviderPricedUsage, ProviderTerminalPricingError> {
        Err(ProviderTerminalPricingError::Unavailable)
    }
}

pub(super) fn start_followup_generation(
    fixture: &super::super::super::fixture::Fixture,
    conversation_id: runne_domain::id::ConversationId,
    authority: &RuntimeAuthorityId,
) -> runne_domain::id::TaskRunId {
    let service = TaskRunService::new(
        fixture.database.store.clone(),
        fixture.database.store.clone(),
        fixture.database.store.clone(),
        authority.clone(),
    );
    let input = TaskRunInput::new("new legal generation".into())
        .unwrap()
        .with_requested_model("fixture-model".into())
        .unwrap()
        .with_selected_profile(
            SelectedProviderProfile::new("fixture-profile-v1".into(), [2; 32]).unwrap(),
        )
        .unwrap();
    let outcome = service
        .submit_task_run(
            &super::super::context(0xc3, "remote-cancel-follow-up-submit"),
            runne_application::commands::SubmitTaskRunInput {
                conversation_id,
                workspace_id: runne_domain::id::WorkspaceId::from_bytes(super::super::WORKSPACE),
                input,
            },
        )
        .unwrap();
    let runne_application::commands::CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = outcome
    else {
        panic!("submitted follow-up TaskRun expected")
    };
    let identity = &fixture.claim_identity;
    let claim = service
        .claim_task_run(
            &super::super::context(0xc4, "remote-cancel-follow-up-claim"),
            ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id: identity.node_id.clone(),
                node_epoch: identity.node_epoch,
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 30_000,
            },
            &fixture.database.store,
        )
        .unwrap();
    let runne_application::ports::TaskRunClaimResult::Committed(claim) = claim else {
        panic!("follow-up claim expected")
    };
    runne_application::conversation_text_service::ConversationTextService::new(
        fixture.database.store.clone(),
        fixture.database.store.clone(),
        authority.clone(),
        super::super::guard(),
    )
    .begin_claimed_text(
        &super::super::context(0xc5, "remote-cancel-follow-up-generation"),
        runne_application::commands::BeginClaimedConversationTextInput {
            original: runne_application::commands::BeginConversationTextInput {
                conversation_id,
                expected_version: 3,
                text: MessageText::new("new legal generation").unwrap(),
            },
            taskrun_id,
            attempt_id: claim.attempt_id,
            taskrun_version: claim.new_version,
            workspace_id: runne_domain::id::WorkspaceId::from_bytes(super::super::WORKSPACE),
            assignment: runne_application::ports::TaskRunAssignmentIdentity {
                taskrun_id,
                attempt_id: claim.attempt_id,
                node_id: identity.node_id.clone(),
                node_epoch: identity.node_epoch,
                fence: claim.fence,
            },
        },
    )
    .unwrap();
    taskrun_id
}
