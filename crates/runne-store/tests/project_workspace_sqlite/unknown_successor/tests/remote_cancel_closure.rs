use self::support::Price;
use super::*;
use runne_application::commands::{
    CancelTaskRunInput, ConversationTextCompletion, FinishConversationTextInput,
};
use runne_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
use runne_application::ports::ProviderRemoteArtifactCancellationEvidence;
use runne_application::provider::ProviderRemoteRecoveryStore;
use runne_application::service::TaskRunService;
use runne_domain::message::MessageText;
use runne_domain::task_run::TaskRunState;
use runne_provider::{
    ProviderRecoveryBinding, ProviderRecoveryOperation, ProviderRemoteCheck,
    ProviderRemoteResponseStatus, ProviderRemoteTerminalArtifact,
    ProviderResponseIdentityCommitter, ProviderUsage, RemoteResponseId,
};
use runne_runtime::provider_execution::{
    ProviderRemoteTerminalSourceOutcome, RuntimeProviderRemoteIdentityCommitter,
};
use std::sync::Arc;

mod audit_ack;
#[path = "remote_cancel_closure/audit_first.rs"]
mod audit_first;
#[path = "remote_cancel_closure/pending_replay.rs"]
mod pending_replay;
mod support;

#[test]
fn cancel_before_first_source_pins_cancel_version_and_reopens_after_next_generation() {
    let fixture = running_with_remote_id(
        "remote-cancel-before-source",
        0xb1,
        "resp_cancel_before_source",
    );
    let attempt_bytes: Vec<u8> = fixture
        .database
        .connection()
        .query_row(
            "SELECT dispatch_attempt_id FROM provider_remote_request_intents WHERE taskrun_id=?1",
            [fixture.taskrun_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    let attempt = runne_provider::DispatchAttemptId::from_bytes(
        attempt_bytes.try_into().expect("dispatch id is 16 bytes"),
    );
    let snapshot = fixture
        .execution
        .load_remote_attempt(attempt)
        .unwrap()
        .unwrap();
    let binding = snapshot.request.binding.clone();
    let recovery = ProviderRecoveryBinding::new(
        binding.taskrun_id,
        binding.taskrun_attempt_id,
        binding.dispatch_attempt_id,
        binding.profile_digest,
    )
    .unwrap();
    let authority_id = runne_application::ports::RuntimeAuthorityId(
        binding
            .runtime_authority_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    );
    let keyring = Arc::new(super::super::effect::Keyring);
    let committer = RuntimeProviderRemoteIdentityCommitter::new(
        Arc::clone(&keyring),
        Arc::clone(&fixture.execution),
    );
    let response_id = RemoteResponseId::new("resp_cancel_before_source").unwrap();
    let proof = fixture
        .execution
        .issue_remote_operation_proof(
            &binding,
            &response_id,
            ProviderRecoveryOperation::StatusCheck,
        )
        .unwrap();
    let status = ProviderRemoteResponseStatus::Completed {
        usage: Some(ProviderUsage::new(3, 4, 0, 0).unwrap()),
    };
    let terminal = ProviderRemoteTerminalArtifact::new(
        response_id.clone(),
        status.clone(),
        Some("completed while cancellation was pending".into()),
    )
    .unwrap();
    let check = ProviderRemoteCheck::new_authorized(
        recovery,
        response_id,
        status,
        Some(terminal),
        ProviderRecoveryOperation::StatusCheck,
        proof,
    )
    .unwrap();
    futures::executor::block_on(committer.persist_remote_check(&check)).unwrap();

    let cancel_context = context(0xc1, "remote-cancel-before-source");
    TaskRunService::new(
        fixture.database.store.clone(),
        fixture.database.store.clone(),
        fixture.database.store.clone(),
        authority_id.clone(),
    )
    .cancel_task_run(
        &cancel_context,
        CancelTaskRunInput {
            taskrun_id: fixture.taskrun_id,
            expected_version: fixture.version,
        },
    )
    .unwrap();
    let cancelled = fixture
        .database
        .store
        .load_task_run(fixture.taskrun_id)
        .unwrap();
    let cancellation = cancelled
        .events
        .iter()
        .find(|event| {
            event.payload() == &runne_domain::task_run::TaskRunEvent::CancellationRequested
        })
        .expect("durable cancellation event");
    let cancel_command = *cancellation.command_id().as_bytes();
    let cancel_event = *cancellation.event_id().as_bytes();
    let cancel_version = cancellation.sequence();

    assert!(
        committer
            .load_persisted_attempt(recovery)
            .unwrap()
            .is_some()
    );
    assert!(
        committer
            .load_persisted_remote_terminal(recovery)
            .unwrap()
            .is_some()
    );

    assert_eq!(
        committer
            .commit_authenticated_remote_terminal_source(recovery, &Price)
            .unwrap(),
        ProviderRemoteTerminalSourceOutcome::AuditOnly
    );
    let artifact_digest = *fixture
        .execution
        .load_remote_attempt(attempt)
        .unwrap()
        .unwrap()
        .terminal
        .unwrap()
        .encrypted_artifact
        .plaintext_digest();
    let evidence = ProviderRemoteArtifactCancellationEvidence::new(
        *attempt.as_bytes(),
        artifact_digest,
        runne_application::provider::ProviderRemoteTerminalDisposition::Completed,
        cancel_command,
        cancel_event,
        cancel_version,
    )
    .unwrap();
    let connection = fixture.database.connection();
    let begin_command = runne_domain::id::CommandId::from_bytes(
        connection
            .query_row(
                "SELECT begin_command_id FROM provider_remote_terminal_settlements WHERE dispatch_attempt_id=?1",
                [attempt.as_bytes().as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .unwrap()
            .try_into()
            .unwrap(),
    );
    drop(connection);
    let generation_key = key("unknown-successor-generation");
    let started = fixture
        .database
        .store
        .load_text_generation_receipt_by_command(begin_command, &generation_key)
        .unwrap();
    let replay_started = started.clone();
    let conversation_id = started.conversation_id;
    let text = ConversationTextService::new(
        fixture.database.store.clone(),
        fixture.database.store.clone(),
        authority_id.clone(),
        guard(),
    );
    let finish_context = context(0xb3, "unknown-successor-generation");
    assert_eq!(finish_context.command_id, begin_command);
    text.finish_text(
        &finish_context,
        FinishConversationTextInput {
            original: runne_application::commands::BeginConversationTextInput {
                conversation_id,
                expected_version: 1,
                text: MessageText::new("successor fixture request").unwrap(),
            },
            started,
            completion: ConversationTextCompletion::RemoteArtifactSettledCancellation { evidence },
        },
    )
    .unwrap();

    let followup_id = support::start_followup_generation(&fixture, conversation_id, &authority_id);
    let replay = text
        .finish_text(
            &finish_context,
            FinishConversationTextInput {
                original: runne_application::commands::BeginConversationTextInput {
                    conversation_id,
                    expected_version: 1,
                    text: MessageText::new("successor fixture request").unwrap(),
                },
                started: replay_started.clone(),
                completion: ConversationTextCompletion::RemoteArtifactSettledCancellation {
                    evidence,
                },
            },
        )
        .unwrap();
    assert_eq!(
        replay.phase,
        runne_application::ports::TextGenerationPhase::Rejected
    );
    let wrong_proof_kind = text.finish_text(
        &finish_context,
        FinishConversationTextInput {
            original: runne_application::commands::BeginConversationTextInput {
                conversation_id,
                expected_version: 1,
                text: MessageText::new("successor fixture request").unwrap(),
            },
            started: replay_started,
            completion: ConversationTextCompletion::NoProviderAdmissionCancellation {
                evidence: runne_application::ports::ProviderNoAdmissionCancellationEvidence {
                    cancellation_taskrun_version: cancel_version,
                },
            },
        },
    );
    assert!(wrong_proof_kind.is_err());
    let reopened = crate::validated_reopen::reopen_store(
        fixture.database.file.path(),
        fixture.database.identity,
        authority_id,
        guard(),
    )
    .unwrap();
    assert_eq!(
        reopened
            .load_task_run(fixture.taskrun_id)
            .unwrap()
            .current_version,
        cancel_version + 1
    );
    assert_eq!(
        runne_domain::task_run::TaskRun::replay(
            &reopened.load_task_run(followup_id).unwrap().events
        )
        .unwrap()
        .state(),
        TaskRunState::Running
    );
}
