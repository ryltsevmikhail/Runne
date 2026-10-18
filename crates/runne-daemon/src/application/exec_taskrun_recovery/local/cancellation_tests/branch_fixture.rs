use runne_application::commands::{CancelTaskRunInput, CommandOutcome, SubmitTaskRunInput};
use runne_application::conversation_service::ConversationService;
use runne_application::ports::{
    ApplicationCommandContext, ExecutionNodeId, ProjectWorkspaceRepository, TaskRunClaimResult,
};
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_application::service::{ClaimTaskRunInput, TaskRunService};
use runne_domain::event::Actor;
use runne_domain::id::{CommandId, IdempotencyKey};
use runne_domain::project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace};
use runne_domain::task_run::{TaskRunExecutable, TaskRunInput, TaskRunLocalCommand};
use runne_platform::process_managed_area::{LinuxManagedArea, LinuxManagedAreaRoot};
use runne_security::SecretBroker;
use runne_store::store::StoreTransaction;
use runne_store::{ProjectWorkspaceStore, schema::read_authority_id};
use std::sync::Arc;

pub(super) struct CancellationBranchFixture {
    pub(super) _directory: tempfile::TempDir,
    pub(super) store: StoreTransaction,
    pub(super) taskrun_id: runne_domain::id::TaskRunId,
    pub(super) area: LinuxManagedArea,
    pub(super) worker_epoch: u64,
    pub(super) node: String,
    pub(super) db_path: String,
}

pub(super) fn guard() -> Arc<dyn ProhibitedContentPort> {
    Arc::new(SecretBroker::new().prohibited_content_guard())
}

pub(super) fn context(operation: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: CommandId::from_bytes(*uuid::Uuid::now_v7().as_bytes()),
        idempotency_key: IdempotencyKey::new(operation).unwrap(),
        principal_id: runne_application::ports::PrincipalId("owner".into()),
        actor: Actor::new("cancellation-branch-test").unwrap(),
    }
}

pub(super) fn register_epoch(db_path: &str, node: [u8; 16]) -> u64 {
    let connection = rusqlite::Connection::open(db_path).unwrap();
    let epoch = runne_store::schema::next_launch_generation(&connection).unwrap();
    runne_store::execution_node::register_local_linux_node(
        &connection,
        node,
        epoch,
        runne_store::execution_node::LinuxNodeDescriptor { capacity: 1 },
        300,
    )
    .unwrap();
    epoch
}

/// One CurrentPermission local command crashed inside its durable
/// cancellation window, exactly as recovery meets it: submitted under the
/// node authority, claimed, its attempt row advanced through the legal state
/// chain, and cancelled durably — without any x2 binding, so the stop
/// evidence classification is honestly `Missing`.
pub(super) fn fixture(
    name: &str,
    terminal_state: &str,
    exit_code: Option<i32>,
) -> CancellationBranchFixture {
    let directory = tempfile::tempdir().unwrap();
    let db_path = directory.path().join("event-log.sqlite");
    let db_path = db_path.to_str().unwrap().to_owned();
    let node_bytes = {
        let connection = runne_store::schema::open_managed_connection(
            std::path::Path::new(&db_path),
            runne_store::schema::ConnectionMode::Writer,
        )
        .unwrap();
        runne_store::schema::apply_migrations(&connection).unwrap();
        let authority_id = runne_store::schema::generate_authority_id();
        runne_store::schema::ensure_authority_id(&connection, &authority_id).unwrap();
        runne_store::schema::ensure_event_log_lineage_id(&connection).unwrap();
        read_authority_id(&connection).unwrap().unwrap()
    };
    let node = uuid::Uuid::from_bytes(node_bytes).to_string();
    let authority = runne_application::ports::RuntimeAuthorityId(node.clone());
    let writer = runne_store::schema::open_managed_connection(
        std::path::Path::new(&db_path),
        runne_store::schema::ConnectionMode::Writer,
    )
    .unwrap();
    let reader = runne_store::schema::open_managed_connection(
        std::path::Path::new(&db_path),
        runne_store::schema::ConnectionMode::Reader,
    )
    .unwrap();
    let store = StoreTransaction::open_with_connections(
        &db_path,
        writer,
        reader,
        authority.clone(),
        guard(),
    )
    .unwrap();
    let workspaces = ProjectWorkspaceStore::from_store(store.clone());
    let project_id = runne_domain::id::ProjectId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
    let workspace_id = runne_domain::id::WorkspaceId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
    workspaces
        .create_project(
            "owner",
            CommandId::from_bytes(*uuid::Uuid::now_v7().as_bytes()),
            &IdempotencyKey::new("project").unwrap(),
            Project::create(
                project_id,
                ProjectWorkspaceDisplayName::new(name.into()).unwrap(),
            ),
        )
        .unwrap();
    workspaces
        .create_workspace(
            "owner",
            CommandId::from_bytes(*uuid::Uuid::now_v7().as_bytes()),
            &IdempotencyKey::new("workspace").unwrap(),
            Workspace::create(
                workspace_id,
                project_id,
                ProjectWorkspaceDisplayName::new(name.into()).unwrap(),
            ),
        )
        .unwrap();
    let conversation_id =
        runne_domain::id::ConversationId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
    let conversation_command = CommandId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
    let conversation_key = IdempotencyKey::new("conversation").unwrap();
    let conversation_context = ApplicationCommandContext {
        command_id: conversation_command,
        idempotency_key: conversation_key.clone(),
        principal_id: runne_application::ports::PrincipalId("owner".into()),
        actor: Actor::new("cancellation-branch-test").unwrap(),
    };
    ConversationService::new(store.clone(), store.clone(), authority.clone())
        .create_from_application(
            &conversation_context,
            runne_api::CreateConversationInput {
                conversation_id,
                workspace_id,
                command_id: conversation_command,
                idempotency_key: conversation_key,
                scope: runne_api::ConversationContextScope::Workspace,
            },
        )
        .unwrap();
    let local = TaskRunLocalCommand::new(
        TaskRunExecutable::workspace_relative("bin/tool".into()).unwrap(),
        ".".into(),
        vec!["tool".into()],
        vec![],
    )
    .unwrap();
    let taskruns = TaskRunService::new(
        store.clone(),
        store.clone(),
        store.clone(),
        authority.clone(),
    );
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = taskruns
        .submit_task_run(
            &context("submit"),
            SubmitTaskRunInput {
                conversation_id,
                workspace_id,
                input: TaskRunInput::new("fixture".into())
                    .unwrap()
                    .with_local_command(local)
                    .unwrap(),
            },
        )
        .unwrap()
    else {
        panic!("local command TaskRun submitted");
    };
    let claim_epoch = register_epoch(&db_path, node_bytes);
    let TaskRunClaimResult::Committed(claim) = taskruns
        .claim_task_run(
            &context("claim"),
            ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id: ExecutionNodeId(node.clone()),
                node_epoch: claim_epoch,
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 30_000,
            },
            &store,
        )
        .unwrap()
    else {
        panic!("fresh claim");
    };
    let root = LinuxManagedAreaRoot::open_current_cgroup().unwrap();
    let area = root
        .create_area(
            runne_platform::process_managed_area::ManagedAreaBinding::new(
                *taskrun_id.as_bytes(),
                *claim.attempt_id.as_bytes(),
                *taskrun_id.as_bytes(),
            )
            .unwrap(),
        )
        .unwrap();
    let area_identity = area.identity().to_bytes();
    let connection = rusqlite::Connection::open(&db_path).unwrap();
    connection
        .execute(
            "UPDATE taskrun_local_command_attempts SET attempt_id=?1,node_id=?2,node_epoch=?3,
             fence=?4,managed_area_identity=?5,updated_at=1 WHERE taskrun_id=?6",
            rusqlite::params![
                claim.attempt_id.as_bytes(),
                node_bytes.as_slice(),
                claim_epoch as i64,
                claim.fence.0 as i64,
                area_identity.as_slice(),
                taskrun_id.as_bytes()
            ],
        )
        .unwrap();
    let mut chain: Vec<&str> = vec!["approved", "launch_intent", "release_reserved", "running"];
    if terminal_state != "running" {
        chain.push(terminal_state);
    }
    let last = chain.len() - 1;
    for (index, state) in chain.iter().enumerate() {
        if index == last {
            connection
                .execute(
                    "UPDATE taskrun_local_command_attempts SET state=?1,exit_code=?2,updated_at=1
                     WHERE taskrun_id=?3",
                    rusqlite::params![state, exit_code, taskrun_id.as_bytes()],
                )
                .unwrap();
        } else {
            connection
                .execute(
                    "UPDATE taskrun_local_command_attempts SET state=?1,updated_at=1
                     WHERE taskrun_id=?2",
                    rusqlite::params![state, taskrun_id.as_bytes()],
                )
                .unwrap();
        }
    }
    drop(connection);
    taskruns
        .cancel_task_run(
            &context("cancel"),
            CancelTaskRunInput {
                taskrun_id,
                expected_version: claim.new_version,
            },
        )
        .unwrap();
    let worker_epoch = register_epoch(&db_path, node_bytes);
    CancellationBranchFixture {
        _directory: directory,
        store,
        taskrun_id,
        area,
        worker_epoch,
        node,
        db_path,
    }
}
