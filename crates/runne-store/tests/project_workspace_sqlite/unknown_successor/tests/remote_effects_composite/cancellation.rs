use super::super::*;
use super::support::{
    Prepared, apply_pending_cancellation, assert_cancelled_source_is_audit_only, commit,
    has_assistant_output, prepare, read,
};
use runne_application::commands::{
    BeginConversationTextInput, CancelTaskRunInput, ConversationTextCompletion,
    FinishConversationTextInput,
};
use runne_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
use runne_application::provider::{
    ProviderRemoteLocalDisposition, ProviderRemoteTerminalDisposition,
};
use runne_application::service::TaskRunService;
use runne_domain::message::MessageText;
use runne_domain::task_run::TaskRunEvent;
use runne_provider::{ProviderRemoteResponseStatus, ProviderUsage};
use runne_runtime::provider_execution::ProviderRemoteTerminalSourceOutcome;

#[test]
fn accepted_local_cancel_does_not_confirm_remote_cancelled_when_source_is_completed() {
    let prepared = prepare(
        "remote-effects-cancel-completed",
        0xd4,
        "resp_effects_cancel_completed",
        ProviderRemoteResponseStatus::Completed {
            usage: Some(ProviderUsage::new(3, 4, 0, 0).unwrap()),
        },
        Some("provider completed before local cancellation closed"),
    );
    let (authority, conversation_id) = taskrun_origin(&prepared);
    let cancel_context = context(0xe1, "remote-effects-cancel-completed");
    TaskRunService::new(
        prepared.fixture.database.store.clone(),
        prepared.fixture.database.store.clone(),
        prepared.fixture.database.store.clone(),
        authority.clone(),
    )
    .cancel_task_run(
        &cancel_context,
        CancelTaskRunInput {
            taskrun_id: prepared.fixture.taskrun_id,
            expected_version: prepared.fixture.version,
        },
    )
    .unwrap();
    assert_eq!(
        commit(&prepared),
        ProviderRemoteTerminalSourceOutcome::AuditOnly
    );

    let stream = prepared
        .fixture
        .database
        .store
        .load_task_run(prepared.fixture.taskrun_id)
        .unwrap();
    let cancellation = stream
        .events
        .iter()
        .find(|event| event.payload() == &TaskRunEvent::CancellationRequested)
        .unwrap();
    let evidence = runne_application::ports::ProviderRemoteArtifactCancellationEvidence::new(
        *prepared.attempt.as_bytes(),
        prepared.artifact_digest,
        ProviderRemoteTerminalDisposition::Completed,
        *cancellation.command_id().as_bytes(),
        *cancellation.event_id().as_bytes(),
        cancellation.sequence(),
    )
    .unwrap();
    let connection = prepared.fixture.database.connection();
    let begin_bytes: Vec<u8> = connection
        .query_row(
            "SELECT begin_command_id FROM provider_remote_terminal_settlements WHERE dispatch_attempt_id=?1",
            [prepared.attempt.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    drop(connection);
    let begin_command = runne_domain::id::CommandId::from_bytes(begin_bytes.try_into().unwrap());
    let generation_key = key("unknown-successor-generation");
    let started = prepared
        .fixture
        .database
        .store
        .load_text_generation_receipt_by_command(begin_command, &generation_key)
        .unwrap();
    ConversationTextService::new(
        prepared.fixture.database.store.clone(),
        prepared.fixture.database.store.clone(),
        authority,
        guard(),
    )
    .finish_text(
        &context(0xd6, "unknown-successor-generation"),
        FinishConversationTextInput {
            original: BeginConversationTextInput {
                conversation_id,
                expected_version: 1,
                text: MessageText::new("successor fixture request").unwrap(),
            },
            started,
            completion: ConversationTextCompletion::RemoteArtifactSettledCancellation { evidence },
        },
    )
    .unwrap();

    let snapshot = read(&prepared);
    let remote = snapshot.remote.unwrap();
    assert_eq!(
        remote.local_disposition,
        ProviderRemoteLocalDisposition::AcceptedCancellationClosed
    );
    assert_eq!(
        snapshot.effects.remote.outcome,
        runne_api::RemoteEffectOutcomeV1::Completed
    );
    assert_eq!(
        snapshot.effects.remote.cancellation,
        runne_api::RemoteCancellationV1::Unconfirmed,
        "local cancellation closure cannot rewrite the factual provider status"
    );
    assert_eq!(
        snapshot.effects.remote.accounting,
        runne_api::RemoteAccountingV1::Known
    );
    assert_eq!(snapshot.effects.remote.usage_known, Some(true));
    assert_eq!(
        snapshot.effects.remote.publication,
        runne_api::RemotePublicationV1::Withheld
    );
    assert_cancelled_source_is_audit_only(&prepared);
    assert!(!has_assistant_output(&prepared.fixture, conversation_id));
}

#[test]
fn cancellation_ack_of_saved_publishable_completion_stays_audit_only() {
    let prepared = prepare(
        "remote-effects-publishable-cancel",
        0xd5,
        "resp_effects_publishable_cancel",
        ProviderRemoteResponseStatus::Completed {
            usage: Some(ProviderUsage::new(3, 4, 0, 0).unwrap()),
        },
        Some("saved output withheld after accepted cancellation"),
    );
    assert_eq!(
        commit(&prepared),
        ProviderRemoteTerminalSourceOutcome::CurrentGeneration
    );
    let (published_output_digest, settlement_state): (Option<Vec<u8>>, i64) = prepared
        .fixture
        .database
        .connection()
        .query_row(
            "SELECT published_output_digest,settlement_state
             FROM provider_remote_terminal_settlements WHERE dispatch_attempt_id=?1",
            [prepared.attempt.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert!(
        published_output_digest.is_some(),
        "fixture pins the authentic output digest"
    );
    assert_eq!(settlement_state, 2);

    let (authority, conversation_id) = taskrun_origin(&prepared);
    TaskRunService::new(
        prepared.fixture.database.store.clone(),
        prepared.fixture.database.store.clone(),
        prepared.fixture.database.store.clone(),
        authority.clone(),
    )
    .cancel_task_run(
        &context(0xe2, "remote-effects-publishable-cancel"),
        CancelTaskRunInput {
            taskrun_id: prepared.fixture.taskrun_id,
            expected_version: prepared.fixture.version,
        },
    )
    .unwrap();
    apply_pending_cancellation(&prepared, &authority);

    let snapshot = read(&prepared);
    let remote = snapshot.remote.unwrap();
    assert_eq!(
        remote.local_disposition,
        ProviderRemoteLocalDisposition::AcceptedCancellationClosed
    );
    assert_eq!(
        snapshot.effects.remote.outcome,
        runne_api::RemoteEffectOutcomeV1::Completed
    );
    assert_eq!(
        snapshot.effects.remote.cancellation,
        runne_api::RemoteCancellationV1::Unconfirmed
    );
    assert_eq!(
        snapshot.effects.remote.publication,
        runne_api::RemotePublicationV1::Withheld
    );
    assert_eq!(
        snapshot.effects.remote.accounting,
        runne_api::RemoteAccountingV1::Known
    );
    assert!(!has_assistant_output(&prepared.fixture, conversation_id));
    let acked_state: i64 = prepared
        .fixture
        .database
        .connection()
        .query_row(
            "SELECT settlement_state FROM provider_remote_terminal_settlements WHERE dispatch_attempt_id=?1",
            [prepared.attempt.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(acked_state, 4, "the saved factual source was acknowledged");

    let legacy = prepared
        .fixture
        .database
        .store
        .load_task_run_effects(prepared.fixture.taskrun_id)
        .unwrap();
    assert_eq!(
        legacy.remote.outcome,
        runne_api::RemoteEffectOutcomeV1::Unknown,
        "the legacy no-authenticator query remains conservative"
    );
}

fn taskrun_origin(
    prepared: &Prepared,
) -> (
    runne_application::ports::RuntimeAuthorityId,
    runne_domain::id::ConversationId,
) {
    let stream = prepared
        .fixture
        .database
        .store
        .load_task_run(prepared.fixture.taskrun_id)
        .unwrap();
    let conversation = stream
        .events
        .iter()
        .find_map(|event| match event.payload() {
            TaskRunEvent::TaskRunSubmitted {
                conversation_id, ..
            } => Some(*conversation_id),
            _ => None,
        });
    (
        runne_application::ports::RuntimeAuthorityId("01010101010101010101010101010101".into()),
        conversation.unwrap(),
    )
}
