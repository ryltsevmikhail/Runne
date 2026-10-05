use super::*;

#[test]
fn direct_no_admission_cancel_closes_with_exact_legacy_origin_and_rejects_d2_marker() {
    let runtime_authority = super::super::super::fixture::runtime_authority();
    let database = Database::new_with_database_authority(
        "no-admission-direct",
        runtime_authority.clone(),
        [1; 16],
    );
    let repository = database.repository();
    repository
        .create_project(
            "principal-1",
            command(1),
            &key("direct-project"),
            project(PROJECT, "Direct"),
        )
        .unwrap();
    repository
        .create_workspace(
            "principal-1",
            command(2),
            &key("direct-workspace"),
            workspace(WORKSPACE, PROJECT, "Direct workspace"),
        )
        .unwrap();
    let conversation_id = ConversationId::from_bytes(command(0x61).into_bytes());
    ConversationService::new(
        database.store.clone(),
        database.store.clone(),
        runtime_authority.clone(),
    )
    .create_from_application(
        &context(0x62, "direct-conversation"),
        runne_api::CreateConversationInput {
            conversation_id,
            workspace_id: WorkspaceId::from_bytes(WORKSPACE),
            command_id: command(0x62),
            idempotency_key: key("direct-conversation"),
            scope: runne_api::ConversationContextScope::Workspace,
        },
    )
    .unwrap();
    let begin_context = context(0x63, "direct-text-begin");
    let text = ConversationTextService::new(
        database.store.clone(),
        database.store.clone(),
        runtime_authority.clone(),
        guard(),
    );
    let started = text
        .begin(
            &begin_context,
            BeginConversationTextInput {
                conversation_id,
                expected_version: 1,
                text: MessageText::new("direct request").unwrap(),
            },
        )
        .unwrap();
    let (execution, launch) = super::super::super::fixture::dispatch::runtime_launch(&database);
    let cancellation_version = request_cancel(&database, &started);
    assert_fresh_issue_denied(&database, &execution, &launch, &started, "principal-1");
    close_cancelled_without_admission(
        &database,
        begin_context.clone(),
        started.clone(),
        "direct request",
        cancellation_version,
    );
    assert_no_provider_effects(&database, started.taskrun_id, started.attempt_id);

    let reopened = crate::validated_reopen::reopen_store(
        database.file.path(),
        database.identity,
        runtime_authority.clone(),
        guard(),
    )
    .unwrap();
    let reopened_text = ConversationTextService::new(
        reopened.clone(),
        reopened.clone(),
        runtime_authority,
        guard(),
    );
    let input = FinishConversationTextInput {
        original: BeginConversationTextInput {
            conversation_id: started.conversation_id,
            expected_version: started.conversation_version - 1,
            text: MessageText::new("direct request").unwrap(),
        },
        started: started.clone(),
        completion: ConversationTextCompletion::NoProviderAdmissionCancellation {
            evidence: runne_application::ports::ProviderNoAdmissionCancellationEvidence {
                cancellation_taskrun_version: started.taskrun_version + 1,
            },
        },
    };
    let replay = reopened_text
        .finish_text(&begin_context, input.clone())
        .unwrap();
    assert_eq!(
        replay.phase,
        runne_application::ports::TextGenerationPhase::Rejected
    );
    assert_no_assistant_output(&reopened, started.conversation_id);
    assert_eq!(
        reopened_text
            .finish_text(&begin_context, input.clone())
            .unwrap(),
        replay
    );

    let marker = database.connection();
    marker
        .execute(
            "INSERT INTO taskrun_tool_budgets
             (taskrun_id,attempt_id,fence,node_id,node_epoch,reservation_id,reservation_digest,
              policy_revision,effects_limit,continuations_limit,effects_used,continuations_used,updated_at)
             VALUES (?1,?2,1,'injected-d2-marker',1,?3,?4,
              'd2-safe-tool-loop-budget-v1',2,2,0,0,1)",
            rusqlite::params![
                started.taskrun_id.as_bytes(),
                started.attempt_id.as_bytes(),
                [0xa1u8; 16].as_slice(),
                [0xb2u8; 32].as_slice(),
            ],
        )
        .unwrap();
    drop(marker);
    assert!(reopened_text.finish_text(&begin_context, input).is_err());
}
