use super::audit_ack::source_ack_snapshot;
use super::support::UnavailablePricing;
use super::*;
use runne_application::commands::{
    CancelTaskRunInput, ConversationTextCompletion, FinishConversationTextInput,
};
use runne_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
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

#[test]
fn audit_source_then_cancel_closes_only_original_generation() {
    let fixture = super::running_with_remote_id(
        "remote-audit-before-cancel",
        0xd1,
        "resp_audit_before_cancel",
    );
    let snapshot = fixture
        .execution
        .load_remote_attempt(super::support::attempt(&fixture))
        .unwrap()
        .unwrap();
    let binding = snapshot.request.binding.clone();
    let authority = super::support::authority(&binding.runtime_authority_id);
    let submitted = fixture
        .database
        .store
        .load_task_run(fixture.taskrun_id)
        .unwrap();
    let conversation_id = submitted
        .events
        .iter()
        .find_map(|event| match event.payload() {
            runne_domain::task_run::TaskRunEvent::TaskRunSubmitted {
                conversation_id, ..
            } => Some(*conversation_id),
            _ => None,
        })
        .expect("submitted task has conversation source");
    let prior_writer = fixture
        .database
        .connection()
        .query_row(
            "SELECT fencing_token FROM conversation_writer_leases WHERE conversation_id=?1",
            [conversation_id.as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    fixture
        .database
        .store
        .take_control_conversation_writer_lease(
            conversation_id.as_bytes(),
            "second-audit-writer",
            u64::try_from(prior_writer).unwrap(),
        )
        .unwrap();

    let recovery = ProviderRecoveryBinding::new(
        binding.taskrun_id,
        binding.taskrun_attempt_id,
        binding.dispatch_attempt_id,
        binding.profile_digest,
    )
    .unwrap();
    let keyring = Arc::new(super::super::super::effect::Keyring);
    let committer = RuntimeProviderRemoteIdentityCommitter::new(
        Arc::clone(&keyring),
        Arc::clone(&fixture.execution),
    );
    let response_id = RemoteResponseId::new("resp_audit_before_cancel").unwrap();
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
    let artifact = ProviderRemoteTerminalArtifact::new(
        response_id.clone(),
        status.clone(),
        Some("audit-only completed text".into()),
    )
    .unwrap();
    let check = ProviderRemoteCheck::new_authorized(
        recovery,
        response_id,
        status,
        Some(artifact),
        ProviderRecoveryOperation::StatusCheck,
        proof,
    )
    .unwrap();
    futures::executor::block_on(committer.persist_remote_check(&check)).unwrap();
    assert_eq!(
        committer
            .commit_authenticated_remote_terminal_source(recovery, &UnavailablePricing)
            .unwrap(),
        ProviderRemoteTerminalSourceOutcome::AuditOnly,
    );
    assert!(!super::support::has_assistant_output(
        &fixture,
        conversation_id
    ));
    super::support::assert_discoverable(&fixture, binding.dispatch_attempt_id);
    let before_cancel = source_ack_snapshot(&fixture, binding.dispatch_attempt_id.as_bytes());
    assert_eq!(before_cancel.state, 3, "audit-only source remains distinct");
    assert_eq!(before_cancel.usage, (Some(3), Some(4), Some(0), Some(0)));
    assert_eq!(
        before_cancel.financial_fields,
        (None, None, None),
        "audit-only source does not claim a known financial settlement"
    );
    assert!(before_cancel.application_receipt.is_none());
    assert_eq!(
        before_cancel.outbox_count, 0,
        "audit-only source has no outbox"
    );
    assert_eq!(before_cancel.known_ledger_count, 0);
    assert_eq!(before_cancel.held_reservations, 2);

    let cancel_context = super::context(0xe1, "remote-audit-before-cancel");
    TaskRunService::new(
        fixture.database.store.clone(),
        fixture.database.store.clone(),
        fixture.database.store.clone(),
        authority.clone(),
    )
    .cancel_task_run(
        &cancel_context,
        CancelTaskRunInput {
            taskrun_id: fixture.taskrun_id,
            expected_version: fixture.version,
        },
    )
    .unwrap();
    super::support::assert_discoverable(&fixture, binding.dispatch_attempt_id);
    let canceled = fixture
        .database
        .store
        .load_task_run(fixture.taskrun_id)
        .unwrap();
    let requested = canceled
        .events
        .iter()
        .find(|event| {
            event.payload() == &runne_domain::task_run::TaskRunEvent::CancellationRequested
        })
        .unwrap();
    let cancellation = runne_application::ports::ProviderRemoteArtifactCancellationEvidence::new(
        *binding.dispatch_attempt_id.as_bytes(),
        *fixture
            .execution
            .load_remote_attempt(super::support::attempt(&fixture))
            .unwrap()
            .unwrap()
            .terminal
            .unwrap()
            .encrypted_artifact
            .plaintext_digest(),
        runne_application::provider::ProviderRemoteTerminalDisposition::Completed,
        *requested.command_id().as_bytes(),
        *requested.event_id().as_bytes(),
        requested.sequence(),
    )
    .unwrap();
    let begin_command = runne_domain::id::CommandId::from_bytes(
        fixture.database.connection().query_row(
            "SELECT begin_command_id FROM provider_remote_terminal_settlements WHERE dispatch_attempt_id=?1",
            [binding.dispatch_attempt_id.as_bytes().as_slice()], |row| row.get::<_, Vec<u8>>(0),
        ).unwrap().try_into().unwrap(),
    );
    let started = fixture
        .database
        .store
        .load_text_generation_receipt_by_command(
            begin_command,
            &super::key("unknown-successor-generation"),
        )
        .unwrap();
    let started_again = started.clone();
    let before = source_ack_snapshot(&fixture, binding.dispatch_attempt_id.as_bytes());
    let service = ConversationTextService::new(
        fixture.database.store.clone(),
        fixture.database.store.clone(),
        authority.clone(),
        super::guard(),
    );
    let context = super::context(0xd3, "unknown-successor-generation");
    let input = || FinishConversationTextInput {
        original: runne_application::commands::BeginConversationTextInput {
            conversation_id,
            expected_version: 1,
            text: MessageText::new("successor fixture request").unwrap(),
        },
        started: started_again.clone(),
        completion: ConversationTextCompletion::RemoteArtifactSettledCancellation {
            evidence: cancellation,
        },
    };
    service
        .finish_text(&context, FinishConversationTextInput { started, ..input() })
        .unwrap();

    let recovery = ProviderRecoveryBinding::new(
        binding.taskrun_id,
        binding.taskrun_attempt_id,
        binding.dispatch_attempt_id,
        binding.profile_digest,
    )
    .unwrap();
    assert_eq!(
        committer
            .commit_authenticated_remote_terminal_source(recovery, &UnavailablePricing)
            .unwrap(),
        ProviderRemoteTerminalSourceOutcome::AuditOnly,
        "the next cached-terminal observation records the cancellation witness"
    );
    super::support::assert_not_discoverable(&fixture);
    super::support::assert_audit_receipt_exists(&fixture, binding.dispatch_attempt_id);
    assert!(!super::support::has_assistant_output(
        &fixture,
        conversation_id
    ));
    assert_eq!(before.state, 3);
    let after = source_ack_snapshot(&fixture, binding.dispatch_attempt_id.as_bytes());
    assert_eq!(
        before, after,
        "late cancellation must not rewrite audited fact or finance"
    );

    let current_fence = fixture
        .database
        .connection()
        .query_row(
            "SELECT fencing_token FROM conversation_writer_leases WHERE conversation_id=?1",
            [conversation_id.as_bytes().as_slice()],
            |row| row.get::<_, i64>(0),
        )
        .unwrap();
    fixture
        .database
        .store
        .take_control_conversation_writer_lease(
            conversation_id.as_bytes(),
            "principal-1",
            u64::try_from(current_fence).unwrap(),
        )
        .unwrap();
    let successor =
        super::support::start_followup_generation(&fixture, conversation_id, &authority);
    let replay = service.finish_text(&context, input()).unwrap();
    assert_eq!(
        replay.phase,
        runne_application::ports::TextGenerationPhase::Rejected
    );
    let reopened = crate::validated_reopen::reopen_store(
        fixture.database.file.path(),
        fixture.database.identity,
        authority,
        super::guard(),
    )
    .unwrap();
    assert_eq!(
        runne_domain::task_run::TaskRun::replay(&reopened.load_task_run(successor).unwrap().events)
            .unwrap()
            .state(),
        TaskRunState::Running,
    );
    assert_eq!(
        source_ack_snapshot(&fixture, binding.dispatch_attempt_id.as_bytes()),
        before,
        "cancellation, successor progress, and reopen preserve the audit-only source"
    );
}
