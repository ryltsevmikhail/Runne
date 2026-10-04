use super::*;
use runne_application::commands::CancelTaskRunInput;

#[test]
fn restart_keeps_a_valid_post_begin_cancellation_pending_and_occupied() {
    let directory = tempfile::tempdir().unwrap();
    let config = ConfigurationSnapshot::from_defaults(&BuiltInDefaults::new(directory.path()));
    let db_path = config.db_path.clone();
    let bootstrap = bootstrap(&config).unwrap();
    let lineage = ensure_event_log_lineage_id(&bootstrap.db_conn).unwrap();
    let authority = RuntimeAuthorityId(hex::encode(bootstrap.authority_id));
    let prohibited: Arc<dyn ProhibitedContentPort> =
        Arc::new(SecretBroker::new().prohibited_content_guard());
    let store = StoreTransaction::open_with_connections(
        &db_path,
        open_runtime_connection(
            &db_path,
            ConnectionMode::ValidatedReopen,
            bootstrap.authority_id,
            lineage,
            "test writer",
        )
        .unwrap(),
        open_runtime_connection(
            &db_path,
            ConnectionMode::Reader,
            bootstrap.authority_id,
            lineage,
            "test reader",
        )
        .unwrap(),
        authority.clone(),
        Arc::clone(&prohibited),
    )
    .unwrap();

    let project_id = "018f2e3a-7000-7000-8000-000000000111".parse().unwrap();
    let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-000000000112".parse().unwrap();
    let workspaces = ProjectWorkspaceStore::from_store(store.clone());
    workspaces
        .create_project(
            "local-owner",
            "018f2e3a-7000-7000-8000-000000000113".parse().unwrap(),
            &IdempotencyKey::new("pending-cancel-project").unwrap(),
            Project::create(
                project_id,
                ProjectWorkspaceDisplayName::new("Startup cancellation".into()).unwrap(),
            ),
        )
        .unwrap();
    workspaces
        .create_workspace(
            "local-owner",
            "018f2e3a-7000-7000-8000-000000000114".parse().unwrap(),
            &IdempotencyKey::new("pending-cancel-workspace").unwrap(),
            Workspace::create(
                workspace_id,
                project_id,
                ProjectWorkspaceDisplayName::new("Startup cancellation".into()).unwrap(),
            ),
        )
        .unwrap();
    let conversation_id = "018f2e3a-7000-7000-8000-000000000115".parse().unwrap();
    ConversationService::new(store.clone(), store.clone(), authority.clone())
        .create_from_application(
            &context(
                "018f2e3a-7000-7000-8000-000000000116",
                "pending-cancel-conversation",
            ),
            runne_api::CreateConversationInput {
                conversation_id,
                workspace_id,
                command_id: "018f2e3a-7000-7000-8000-000000000116".parse().unwrap(),
                idempotency_key: IdempotencyKey::new("pending-cancel-conversation").unwrap(),
                scope: runne_api::ConversationContextScope::Workspace,
            },
        )
        .unwrap();
    let taskruns = TaskRunService::new(
        store.clone(),
        store.clone(),
        store.clone(),
        authority.clone(),
    );
    let submitted = taskruns
        .submit_task_run(
            &context(
                "018f2e3a-7000-7000-8000-000000000117",
                "pending-cancel-submit",
            ),
            SubmitTaskRunInput {
                conversation_id,
                workspace_id,
                input: runne_domain::task_run::TaskRunInput::new("restart prompt".into()).unwrap(),
            },
        )
        .unwrap();
    let runne_application::commands::CommandOutcome::TaskRunSubmitted { taskrun_id, .. } =
        submitted
    else {
        panic!("TaskRun submission expected")
    };
    let node_id = ExecutionNodeId(uuid::Uuid::from_bytes(bootstrap.authority_id).to_string());
    runne_store::execution_node::register_local_linux_node(
        &bootstrap.db_conn,
        bootstrap.authority_id,
        bootstrap.launch_generation,
        runne_store::execution_node::LinuxNodeDescriptor { capacity: 1 },
        300,
    )
    .unwrap();
    let claimed = taskruns
        .claim_task_run(
            &context(
                "018f2e3a-7000-7000-8000-000000000118",
                "pending-cancel-claim",
            ),
            ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id: node_id.clone(),
                node_epoch: bootstrap.launch_generation,
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 300_000,
            },
            &store,
        )
        .unwrap();
    let TaskRunClaimResult::Committed(claim) = claimed else {
        panic!("TaskRun claim expected")
    };
    let identity = TaskRunAssignmentIdentity {
        taskrun_id,
        attempt_id: claim.attempt_id,
        node_id,
        node_epoch: claim.node_epoch,
        fence: claim.fence,
    };
    let text: Arc<dyn ConversationTextCommandService> = Arc::new(ConversationTextService::new(
        store.clone(),
        store.clone(),
        authority.clone(),
        prohibited.clone(),
    ));
    text.begin_claimed_text(
        &context(
            "018f2e3a-7000-7000-8000-000000000119",
            "pending-cancel-begin",
        ),
        BeginClaimedConversationTextInput {
            original: BeginConversationTextInput {
                conversation_id,
                expected_version: 1,
                text: MessageText::new("restart prompt").unwrap(),
            },
            taskrun_id,
            attempt_id: claim.attempt_id,
            taskrun_version: claim.new_version,
            workspace_id,
            assignment: identity.clone(),
        },
    )
    .unwrap();
    taskruns
        .cancel_task_run(
            &context(
                "018f2e3a-7000-7000-8000-000000000120",
                "pending-cancel-request",
            ),
            CancelTaskRunInput {
                taskrun_id,
                expected_version: claim.new_version,
            },
        )
        .unwrap();
    assert_eq!(
        store.load_task_run(taskrun_id).unwrap().current_version,
        claim.new_version + 1
    );

    // Reopen the durable store as boot does. This exercises the actual
    // startup-settlement hook before HTTP/automatic-worker construction.
    drop(text);
    drop(taskruns);
    drop(store);
    let reopened = StoreTransaction::open_with_connections(
        &db_path,
        open_runtime_connection(
            &db_path,
            ConnectionMode::ValidatedReopen,
            bootstrap.authority_id,
            lineage,
            "reopened writer",
        )
        .unwrap(),
        open_runtime_connection(
            &db_path,
            ConnectionMode::Reader,
            bootstrap.authority_id,
            lineage,
            "reopened reader",
        )
        .unwrap(),
        authority.clone(),
        Arc::clone(&prohibited),
    )
    .unwrap();
    let reopened_text: Arc<dyn ConversationTextCommandService> =
        Arc::new(ConversationTextService::new(
            reopened.clone(),
            reopened.clone(),
            authority.clone(),
            prohibited,
        ));
    // Composition calls this after provider startup settlement and before
    // HTTP startup constructs the automatic TaskRun service.
    assert_eq!(
        settle_interrupted_text_generations(&bootstrap.db_conn, &reopened_text, &authority)
            .unwrap(),
        0
    );
    let taskrun = reopened.load_task_run(taskrun_id).unwrap();
    assert_eq!(taskrun.current_version, claim.new_version + 1);
    let replayed = runne_domain::task_run::TaskRun::replay(&taskrun.events).unwrap();
    assert_eq!(
        replayed.state(),
        runne_domain::task_run::TaskRunState::Cancelling
    );
    assert!(matches!(
        taskrun.events.last().unwrap().payload(),
        runne_domain::task_run::TaskRunEvent::CancellationRequested
    ));
    let receipt_bytes: Vec<u8> = bootstrap
        .db_conn
        .query_row(
            "SELECT command_outcome FROM command_receipts WHERE command_id=?1",
            ["018f2e3a-7000-7000-8000-000000000119"
                .parse::<runne_domain::id::CommandId>()
                .unwrap()
                .as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    let receipt = runne_store::codec::StoreCodec::decode(
        &runne_store::codec::TextGenerationReceiptCodec,
        &receipt_bytes,
    )
    .unwrap();
    assert_eq!(
        receipt.phase,
        runne_application::ports::TextGenerationPhase::Started
    );
    assert_eq!(receipt.taskrun_version, claim.new_version);
    let occupation: String = bootstrap
        .db_conn
        .query_row(
            "SELECT state FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2",
            rusqlite::params![taskrun_id.as_bytes(), identity.fence.0 as i64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(occupation, "active");
    let admissions: i64 = bootstrap
        .db_conn
        .query_row(
            "SELECT count(*) FROM provider_execution_admissions WHERE taskrun_id=?1",
            [taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(admissions, 0);
}
