#![cfg(target_os = "linux")]

use super::super::claim::node_registration;
#[path = "binding.rs"]
mod binding;
use self::binding::matcher_clean_binding;
use super::super::support::*;
use runne_application::commands::{CancelTaskRunInput, CommandOutcome, SubmitTaskRunInput};
use runne_application::conversation_service::ConversationService;
use runne_application::ports::{ExecutionNodeId, TaskRunClaimResult};
use runne_application::service::TaskRunService;
use runne_domain::id::{ConversationId, WorkspaceId};
use runne_domain::task_run::{TaskRunExecutable, TaskRunInput, TaskRunLocalCommand};
use runne_store::store::LocalCommandRecoveryCandidate;

fn task_context_with(
    command_id: runne_domain::id::CommandId,
    idempotency_key: runne_domain::id::IdempotencyKey,
) -> runne_application::ports::ApplicationCommandContext {
    runne_application::ports::ApplicationCommandContext {
        command_id,
        idempotency_key,
        principal_id: runne_application::ports::PrincipalId("owner".into()),
        actor: runne_domain::event::Actor::new("cancellation-recovery-test").unwrap(),
    }
}

pub(super) struct RecoveryFixture {
    pub(super) database: Database,
    pub(super) taskrun_id: runne_domain::id::TaskRunId,
    pub(super) area: runne_platform::process_managed_area::LinuxManagedArea,
}

pub(super) type ReopenedRecovery = (
    runne_store::store::StoreTransaction,
    String,
    u64,
    LocalCommandRecoveryCandidate,
);

/// Builds the crash window the daemon recovery meets: a CurrentPermission
/// local command with a durable `CancellationRequested`, an exact attempt row,
/// and (optionally) the x2 binding the permission stop row must cite.
pub(super) async fn prepare_recovery_fixture(
    name: &str,
    _seed: u8,
    include_binding: bool,
    attempt_state: &str,
    exit_code: Option<i32>,
) -> RecoveryFixture {
    let database = Database::new(name);
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let fresh_command =
        || runne_domain::id::CommandId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
    let conversation_id = ConversationId::from_bytes(*uuid::Uuid::now_v7().as_bytes());
    let conversation_command = fresh_command();
    let conversation_key = key(&format!("{name}-conversation"));
    ConversationService::new(database.store.clone(), database.store.clone(), authority())
        .create_from_application(
            &task_context_with(conversation_command, conversation_key.clone()),
            runne_api::CreateConversationInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
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
    let command_digest = local.intent_digest();
    let (node_id, _) = node_registration(&database);
    let node_store = crate::validated_reopen::reopen_store(
        database.file.path(),
        database.identity,
        runne_application::ports::RuntimeAuthorityId(node_id.clone()),
        guard(),
    )
    .unwrap();
    let node_task_runs = TaskRunService::new(
        node_store.clone(),
        node_store.clone(),
        node_store.clone(),
        runne_application::ports::RuntimeAuthorityId(node_id.clone()),
    );
    let outcome = node_task_runs
        .submit_task_run(
            &task_context_with(fresh_command(), key(name)),
            SubmitTaskRunInput {
                conversation_id,
                workspace_id: WorkspaceId::from_bytes(WORKSPACE),
                input: TaskRunInput::new("fixture".into())
                    .unwrap()
                    .with_local_command(local)
                    .unwrap(),
            },
        )
        .unwrap();
    let CommandOutcome::TaskRunSubmitted { taskrun_id, .. } = outcome else {
        panic!("local command TaskRun submitted");
    };
    let (node_id, node_epoch) = (node_id, node_registration(&database).1);
    let claimed = node_task_runs
        .claim_task_run(
            &task_context_with(fresh_command(), key(&format!("{name}-claim"))),
            runne_application::service::ClaimTaskRunInput {
                taskrun_id,
                expected_version: 2,
                node_id: ExecutionNodeId(node_id.clone()),
                node_epoch,
                capability_descriptor: "linux-executor-v1".into(),
                lease_duration_ms: 30_000,
            },
            &node_store,
        )
        .unwrap();
    let TaskRunClaimResult::Committed(claim) = claimed else {
        panic!("fresh claim");
    };
    let node = uuid::Uuid::parse_str(&node_id).unwrap();
    if include_binding {
        let (blob, digest) = matcher_clean_binding(
            command_digest,
            taskrun_id,
            *claim.attempt_id.as_bytes(),
            node,
            node_epoch,
            claim.fence.0,
            claim.new_version,
        );
        database
            .connection()
            .execute(
                "INSERT INTO x2_permission_bindings(taskrun_id,attempt_id,fence,invocation_id,
                 binding_digest,codec_version,binding,native_owner_id,native_owner_generation,
                 selection_managed_policy_version,selection_managed_policy_digest,captured_at)
                 VALUES(?1,?2,?3,?4,?5,1,?6,?7,?8,0,?9,1)",
                rusqlite::params![
                    taskrun_id.as_bytes(),
                    claim.attempt_id.as_bytes(),
                    claim.fence.0 as i64,
                    [0x81_u8; 16].as_slice(),
                    digest.as_slice(),
                    blob,
                    [0x8d_u8; 16].as_slice(),
                    1_u64.to_be_bytes().as_slice(),
                    [0x8f_u8; 32].as_slice()
                ],
            )
            .unwrap();
    }
    let area_root =
        runne_platform::process_managed_area::LinuxManagedAreaRoot::open_current_cgroup()
            .expect("delegated Linux cgroup-v2 root");
    let area = area_root
        .create_area(
            runne_platform::process_managed_area::ManagedAreaBinding::new(
                *taskrun_id.as_bytes(),
                *claim.attempt_id.as_bytes(),
                *taskrun_id.as_bytes(),
            )
            .unwrap(),
        )
        .expect("private attempt cgroup");
    let area_identity = area.identity().to_bytes();
    database
        .connection()
        .execute(
            "UPDATE taskrun_local_command_attempts SET attempt_id=?1,node_id=?2,node_epoch=?3,
             fence=?4,managed_area_identity=?5,updated_at=1 WHERE taskrun_id=?6",
            rusqlite::params![
                claim.attempt_id.as_bytes(),
                node.as_bytes(),
                node_epoch as i64,
                claim.fence.0 as i64,
                area_identity.as_slice(),
                taskrun_id.as_bytes()
            ],
        )
        .unwrap();
    let mut chain: Vec<&str> = vec!["approved", "launch_intent", "release_reserved", "running"];
    match attempt_state {
        "completed" | "cancel_requested" => chain.push(attempt_state),
        other => panic!("unsupported fixture state {other}"),
    }
    let last = chain.len() - 1;
    for (index, state) in chain.iter().enumerate() {
        let sql = if index == last {
            "UPDATE taskrun_local_command_attempts SET state=?1,exit_code=?2,updated_at=1
             WHERE taskrun_id=?3"
        } else {
            "UPDATE taskrun_local_command_attempts SET state=?1,updated_at=1 WHERE taskrun_id=?2"
        };
        if index == last {
            database
                .connection()
                .execute(
                    sql,
                    rusqlite::params![state, exit_code, taskrun_id.as_bytes()],
                )
                .unwrap();
        } else {
            database
                .connection()
                .execute(sql, rusqlite::params![state, taskrun_id.as_bytes()])
                .unwrap();
        }
    }
    node_task_runs
        .cancel_task_run(
            &task_context_with(fresh_command(), key(&format!("{name}-cancel"))),
            CancelTaskRunInput {
                taskrun_id,
                expected_version: claim.new_version,
            },
        )
        .unwrap();
    RecoveryFixture {
        database,
        taskrun_id,
        area,
    }
}

pub(super) fn reopens_under_full_schema_validation(fixture: &RecoveryFixture) {
    crate::validated_reopen::reopen_store(
        fixture.database.file.path(),
        fixture.database.identity,
        authority(),
        guard(),
    )
    .unwrap();
}

pub(super) fn reopen_recovery_candidate(fixture: &RecoveryFixture) -> ReopenedRecovery {
    let (node_id, epoch) = node_registration(&fixture.database);
    let store = crate::validated_reopen::reopen_store(
        fixture.database.file.path(),
        fixture.database.identity,
        runne_application::ports::RuntimeAuthorityId(node_id.clone()),
        guard(),
    )
    .unwrap();
    let candidate = store
        .scan_local_command_recovery(None, 16)
        .unwrap()
        .into_iter()
        .find(|candidate| candidate.identity.taskrun_id == fixture.taskrun_id)
        .expect("durable cancellation candidate");
    (store, node_id, epoch, candidate)
}

pub(super) fn taskrun_event_count(fixture: &RecoveryFixture) -> i64 {
    fixture
        .database
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM events WHERE aggregate_type=1 AND aggregate_id=?1",
            [fixture.taskrun_id.as_bytes()],
            |row| row.get(0),
        )
        .unwrap()
}

pub(super) fn attempt_row(fixture: &RecoveryFixture) -> (String, Option<i32>) {
    fixture
        .database
        .connection()
        .query_row(
            "SELECT state,exit_code FROM taskrun_local_command_attempts WHERE taskrun_id=?1",
            [fixture.taskrun_id.as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

pub(super) fn scalar(fixture: &RecoveryFixture, sql: &str) -> i64 {
    fixture
        .database
        .connection()
        .query_row(sql, [fixture.taskrun_id.as_bytes()], |row| row.get(0))
        .unwrap()
}
