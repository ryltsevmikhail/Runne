use super::super::super::support::{WORKSPACE, guard};
use super::super::fixture::{Fixture, runtime_authority};
use super::context;
use runne_application::commands::{
    CancelTaskRunInput, SupersedeUnknownTaskRunInput, UnknownSuccessorAcknowledgmentV1,
};
use runne_application::conversation_text_service::ConversationTextCommandService;
use runne_application::ports::{ConversationRepository, EventStore, UnknownSuccessorCommitResult};
use runne_application::provider::{
    HistoricalProviderModelError, HistoricalProviderModelResolver,
    HistoricalProviderProfileIdentity,
};
use runne_application::service::TaskRunService;
use runne_provider::{ModelRef, ProviderId};
use std::sync::Arc;

pub(in super::super) struct Resolver;
impl HistoricalProviderModelResolver for Resolver {
    fn resolve_exact(
        &self,
        identity: &HistoricalProviderProfileIdentity,
    ) -> Result<ModelRef, HistoricalProviderModelError> {
        if identity.profile_id() != "fixture-profile-v1" || identity.profile_digest() != &[2; 32] {
            return Err(HistoricalProviderModelError::ProfileUnavailable);
        }
        Ok(ModelRef::new(
            ProviderId::new(identity.provider_id().as_str()).unwrap(),
            "fixture-model",
            "v1",
        )
        .unwrap())
    }
}

pub(super) fn create_successor(
    fixture: &Fixture,
    tail: u8,
    expected: u64,
) -> runne_domain::id::TaskRunId {
    let service = TaskRunService::new(
        fixture.database.store.clone(),
        fixture.database.store.clone(),
        fixture.database.store.clone(),
        runtime_authority(),
    )
    .with_unknown_successor_repository(Arc::new(
        fixture
            .database
            .store
            .unknown_successor_repository(Arc::new(Resolver)),
    ));
    service
        .supersede_unknown_task_run(
            &context(tail, "unknown-successor-chain-create"),
            SupersedeUnknownTaskRunInput {
                predecessor_taskrun_id: fixture.taskrun_id,
                expected_predecessor_version: expected,
                acknowledgment: UnknownSuccessorAcknowledgmentV1::DuplicateExecutionAndCostV1,
            },
        )
        .unwrap()
        .successor_taskrun_id
}

pub(super) fn start_successor_attempt(
    fixture: Fixture,
    taskrun_id: runne_domain::id::TaskRunId,
    tail: u8,
) -> Fixture {
    let Fixture {
        database,
        credentials,
        execution,
        launch,
        ..
    } = fixture;
    let stream = database.store.load_task_run(taskrun_id).unwrap();
    let (conversation_id, prompt) = match stream.events[0].payload() {
        runne_domain::task_run::TaskRunEvent::TaskRunSubmitted {
            conversation_id,
            input,
            ..
        } => (*conversation_id, input.prompt().to_owned()),
        _ => panic!("operation24 submit origin expected"),
    };
    let conversation = database.store.load_conversation(conversation_id).unwrap();
    let claim = TaskRunService::new(
        database.store.clone(),
        database.store.clone(),
        database.store.clone(),
        runtime_authority(),
    )
    .claim_task_run(
        &context(tail, "unknown-successor-chain-claim"),
        runne_application::service::ClaimTaskRunInput {
            taskrun_id,
            expected_version: 2,
            node_id: fixture.claim_identity.node_id.clone(),
            node_epoch: fixture.claim_identity.node_epoch,
            capability_descriptor: "linux-executor-v1".into(),
            lease_duration_ms: 30_000,
        },
        &database.store,
    )
    .unwrap();
    let runne_application::ports::TaskRunClaimResult::Committed(claim) = claim else {
        panic!("successor claim expected")
    };
    let identity = runne_application::ports::TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id: claim.attempt_id,
        node_id: fixture.claim_identity.node_id,
        node_epoch: fixture.claim_identity.node_epoch,
        fence: claim.fence,
    };
    let text = runne_application::conversation_text_service::ConversationTextService::new(
        database.store.clone(),
        database.store.clone(),
        runtime_authority(),
        guard(),
    );
    text.begin_claimed_text(
        &context(tail + 1, "unknown-successor-chain-start"),
        runne_application::commands::BeginClaimedConversationTextInput {
            original: runne_application::commands::BeginConversationTextInput {
                conversation_id,
                expected_version: conversation.current_version,
                text: runne_domain::message::MessageText::new(prompt).unwrap(),
            },
            taskrun_id,
            attempt_id: claim.attempt_id,
            taskrun_version: claim.new_version,
            workspace_id: runne_domain::id::WorkspaceId::from_bytes(WORKSPACE),
            assignment: identity.clone(),
        },
    )
    .unwrap();
    super::super::fixture::dispatch_unknown(
        &database,
        &credentials,
        &execution,
        &launch,
        &identity,
        conversation_id,
    );
    Fixture {
        database,
        credentials,
        execution,
        launch,
        taskrun_id,
        claim_identity: identity,
        version: claim.new_version,
    }
}

pub(super) fn verify_successor(fixture: Fixture, tail: u8, cancel: bool) {
    let mut expected = fixture.version;
    if cancel {
        TaskRunService::new(
            fixture.database.store.clone(),
            fixture.database.store.clone(),
            fixture.database.store.clone(),
            runtime_authority(),
        )
        .cancel_task_run(
            &context(tail, "cancel-before-successor"),
            CancelTaskRunInput {
                taskrun_id: fixture.taskrun_id,
                expected_version: expected,
            },
        )
        .unwrap();
        expected += 1;
    }
    let eligibility = fixture
        .database
        .store
        .unknown_successor_repository(Arc::new(Resolver));
    assert!(
        eligibility
            .is_eligible(fixture.taskrun_id, expected)
            .unwrap()
    );
    let effects = fixture
        .database
        .store
        .load_task_run_effects_with_remote_authenticator(fixture.taskrun_id, None, Some(&Resolver))
        .unwrap();
    assert_eq!(
        effects.effects.successor,
        runne_api::SuccessorEligibilityV1::RequiresDuplicateEffectAcknowledgment
    );
    assert!(
        !eligibility
            .is_eligible(fixture.taskrun_id, expected + 1)
            .unwrap()
    );
    let service = TaskRunService::new(
        fixture.database.store.clone(),
        fixture.database.store.clone(),
        fixture.database.store.clone(),
        runtime_authority(),
    )
    .with_unknown_successor_repository(Arc::new(
        fixture
            .database
            .store
            .unknown_successor_repository(Arc::new(Resolver)),
    ));
    let result: UnknownSuccessorCommitResult = service
        .supersede_unknown_task_run(
            &context(tail + 1, "unknown-successor-acceptance"),
            SupersedeUnknownTaskRunInput {
                predecessor_taskrun_id: fixture.taskrun_id,
                expected_predecessor_version: expected,
                acknowledgment: UnknownSuccessorAcknowledgmentV1::DuplicateExecutionAndCostV1,
            },
        )
        .unwrap();
    assert_eq!(result.predecessor_taskrun_id, fixture.taskrun_id);
    assert_eq!(result.predecessor_version, expected + 1);
    assert_eq!(result.successor_version, 2);
    let reopened = crate::validated_reopen::reopen_store(
        fixture.database.file.path(),
        fixture.database.identity,
        runtime_authority(),
        guard(),
    )
    .unwrap();
    let predecessor = reopened.load_task_run(fixture.taskrun_id).unwrap();
    let successor = reopened.load_task_run(result.successor_taskrun_id).unwrap();
    assert_eq!(predecessor.current_version, expected + 1);
    assert_eq!(
        runne_domain::task_run::TaskRun::replay(&predecessor.events)
            .unwrap()
            .state(),
        runne_domain::task_run::TaskRunState::Unrecoverable
    );
    assert_eq!(successor.current_version, 2);
    assert_eq!(
        runne_domain::task_run::TaskRun::replay(&successor.events)
            .unwrap()
            .state(),
        runne_domain::task_run::TaskRunState::Queued
    );
    let receipt_count: i64 = fixture.database.connection().query_row(
        "SELECT COUNT(*) FROM taskrun_unknown_successor_receipts WHERE predecessor_taskrun_id=?1 AND successor_taskrun_id=?2",
        rusqlite::params![fixture.taskrun_id.as_bytes(), result.successor_taskrun_id.as_bytes()], |row| row.get(0),
    ).unwrap();
    assert_eq!(receipt_count, 1);
    let after_commit = fixture
        .database
        .store
        .unknown_successor_repository(Arc::new(Resolver));
    assert!(
        !after_commit
            .is_eligible(fixture.taskrun_id, expected + 1)
            .unwrap()
    );
}
