use super::*;
use crate::config::BuiltInDefaults;
use runne_application::commands::{
    BeginClaimedConversationTextInput, BeginConversationTextInput, SubmitTaskRunInput,
};
use runne_application::conversation_text_service::{
    ConversationTextCommandService, ConversationTextService,
};
use runne_application::ports::{
    ApplicationCommandContext, EventStore, ExecutionNodeId, ProjectWorkspaceRepository,
    TaskRunAssignmentIdentity, TaskRunClaimResult, TaskRunNoEffectScanRequest,
    TaskRunNoEffectScanner,
};
use runne_application::service::{ClaimTaskRunInput, TaskRunService};
use runne_domain::event::Actor;
use runne_domain::id::{IdempotencyKey, WorkspaceId};
use runne_domain::message::MessageText;
use runne_domain::project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace};
use runne_store::{ProjectWorkspaceStore, schema::ConnectionMode, store::StoreTransaction};

mod pending_cancellation;

fn context(command: &str, key: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: command.parse().unwrap(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal_id: runne_application::ports::PrincipalId("local-owner".into()),
        actor: Actor::new("startup-settlement-test").unwrap(),
    }
}

#[test]
fn boot_settles_started_generation_before_old_claim_can_be_released() {
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

    let project_id = "018f2e3a-7000-7000-8000-000000000011".parse().unwrap();
    let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-000000000093".parse().unwrap();
    let workspaces = ProjectWorkspaceStore::from_store(store.clone());
    workspaces
        .create_project(
            "local-owner",
            "018f2e3a-7000-7000-8000-000000000012".parse().unwrap(),
            &IdempotencyKey::new("startup-project").unwrap(),
            Project::create(
                project_id,
                ProjectWorkspaceDisplayName::new("Startup test".into()).unwrap(),
            ),
        )
        .unwrap();
    workspaces
        .create_workspace(
            "local-owner",
            "018f2e3a-7000-7000-8000-000000000013".parse().unwrap(),
            &IdempotencyKey::new("startup-workspace").unwrap(),
            Workspace::create(
                workspace_id,
                project_id,
                ProjectWorkspaceDisplayName::new("Startup test".into()).unwrap(),
            ),
        )
        .unwrap();
    let conversation_id = "018f2e3a-7000-7000-8000-000000000097".parse().unwrap();
    ConversationService::new(store.clone(), store.clone(), authority.clone())
        .create_from_application(
            &context(
                "018f2e3a-7000-7000-8000-000000000098",
                "startup-conversation",
            ),
            runne_api::CreateConversationInput {
                conversation_id,
                workspace_id,
                command_id: "018f2e3a-7000-7000-8000-000000000098".parse().unwrap(),
                idempotency_key: IdempotencyKey::new("startup-conversation").unwrap(),
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
            &context("018f2e3a-7000-7000-8000-000000000099", "startup-submit"),
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
    let node_bytes = bootstrap.authority_id;
    let node_id = ExecutionNodeId(uuid::Uuid::from_bytes(node_bytes).to_string());
    runne_store::execution_node::register_local_linux_node(
        &bootstrap.db_conn,
        node_bytes,
        bootstrap.launch_generation,
        runne_store::execution_node::LinuxNodeDescriptor { capacity: 1 },
        300,
    )
    .unwrap();
    let claim = taskruns
        .claim_task_run(
            &context("018f2e3a-7000-7000-8000-000000000100", "startup-claim"),
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
    let TaskRunClaimResult::Committed(claim) = claim else {
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
        prohibited,
    ));
    let begin_context = context("018f2e3a-7000-7000-8000-000000000101", "startup-begin");
    let original = BeginConversationTextInput {
        conversation_id,
        expected_version: 1,
        text: MessageText::new("restart prompt").unwrap(),
    };
    text.begin_claimed_text(
        &begin_context,
        BeginClaimedConversationTextInput {
            original,
            taskrun_id,
            attempt_id: claim.attempt_id,
            taskrun_version: claim.new_version,
            workspace_id,
            assignment: identity.clone(),
        },
    )
    .unwrap();

    // This is the same startup settlement invoked from provider_startup before
    // HTTP startup constructs the automatic TaskRun service.
    assert_eq!(
        settle_interrupted_text_generations(&bootstrap.db_conn, &text, &authority).unwrap(),
        1
    );
    let run = store.load_task_run(taskrun_id).unwrap();
    assert!(matches!(
        run.events.last().unwrap().payload(),
        runne_domain::task_run::TaskRunEvent::TaskRunFailed { reason }
            if reason == "interrupted_by_restart"
    ));
    assert!(
        store
            .scan_no_effect_assignments(
                TaskRunNoEffectScanRequest::new(
                    None,
                    8,
                    identity.node_id.clone(),
                    bootstrap.launch_generation + 1,
                )
                .unwrap(),
            )
            .unwrap()
            .candidates
            .is_empty()
    );
    let occupation: String = bootstrap
        .db_conn
        .query_row(
            "SELECT state FROM taskrun_assignment_occupations WHERE taskrun_id=?1 AND fence=?2",
            rusqlite::params![taskrun_id.as_bytes(), identity.fence.0 as i64],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(occupation, "released");
}
