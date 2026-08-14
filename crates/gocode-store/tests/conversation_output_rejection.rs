use std::sync::Arc;

use gocode_api::CreateConversationInput;
use gocode_application::commands::{
    BeginConversationTextInput, ConversationTextCompletion, FinishConversationTextInput,
};
use gocode_application::conversation_service::ConversationService;
use gocode_application::conversation_text_service::{
    ConversationTextService, ConversationTextServiceError,
};
use gocode_application::ports::{
    ApplicationCommandContext, CommitError, ConversationRepository, EventStore, PrincipalId,
    ProjectWorkspaceRepository, RuntimeAuthorityId, StorageFailureKind, TextGenerationPhase,
};
use gocode_application::prohibited_content::ProhibitedContentPort;
use gocode_domain::conversation::{Conversation, GenerationFailureReason};
use gocode_domain::event::Actor;
use gocode_domain::id::{CommandId, ConversationId, IdempotencyKey, ProjectId, WorkspaceId};
use gocode_domain::message::MessageText;
use gocode_domain::project_workspace::{Project, ProjectWorkspaceDisplayName, Workspace};
use gocode_domain::task_run::{TaskRun, TaskRunEvent, TaskRunState};
use gocode_security::SecretBroker;
use gocode_store::codec::{StoreCodec, TextGenerationReceiptCodec};
use gocode_store::{ProjectWorkspaceStore, store::StoreTransaction};

type SnapshotState = Vec<(i64, Vec<u8>, Vec<u8>, Vec<u8>)>;

fn available_guard() -> Arc<dyn ProhibitedContentPort> {
    Arc::new(SecretBroker::new().prohibited_content_guard())
}

fn context(command_id: &str, key: &str) -> ApplicationCommandContext {
    ApplicationCommandContext {
        command_id: command_id.parse::<CommandId>().unwrap(),
        idempotency_key: IdempotencyKey::new(key).unwrap(),
        principal_id: PrincipalId("local-owner".into()),
        actor: Actor::new("store-test").unwrap(),
    }
}

#[test]
fn rejected_provider_output_is_terminal_idempotent_and_creates_no_assistant_message() {
    let directory = tempfile::tempdir().unwrap();
    let daemon = directory.path().join("gocode-daemon");
    std::fs::create_dir(&daemon).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let database_path = daemon
        .join("output-rejection.sqlite")
        .to_str()
        .unwrap()
        .to_owned();
    let authority = RuntimeAuthorityId("output-rejection-test".into());
    let store =
        StoreTransaction::open(&database_path, authority.clone(), available_guard()).unwrap();
    let projects = ProjectWorkspaceStore::from_store(store.clone());
    let conversation_id: ConversationId = "018f2e3a-7000-7000-8000-000000000001".parse().unwrap();
    let workspace_id: WorkspaceId = "018f2e3a-7000-7000-8000-000000000002".parse().unwrap();
    let project_id: ProjectId = "018f2e3a-7000-7000-8000-000000000010".parse().unwrap();
    projects
        .create_project(
            "local-owner",
            "018f2e3a-7000-7000-8000-000000000011".parse().unwrap(),
            &IdempotencyKey::new("create-project").unwrap(),
            Project::create(
                project_id,
                ProjectWorkspaceDisplayName::new("Project".into()).unwrap(),
            ),
        )
        .unwrap();
    projects
        .create_workspace(
            "local-owner",
            "018f2e3a-7000-7000-8000-000000000012".parse().unwrap(),
            &IdempotencyKey::new("create-workspace").unwrap(),
            Workspace::create(
                workspace_id,
                project_id,
                ProjectWorkspaceDisplayName::new("Workspace".into()).unwrap(),
            ),
        )
        .unwrap();
    let create_context = context(
        "018f2e3a-7000-7000-8000-000000000003",
        "create-conversation",
    );
    ConversationService::new(store.clone(), store.clone(), authority.clone())
        .create_from_application(
            &create_context,
            CreateConversationInput {
                conversation_id,
                workspace_id,
                command_id: create_context.command_id,
                idempotency_key: create_context.idempotency_key.clone(),
            },
        )
        .unwrap();

    let generation_context = context("018f2e3a-7000-7000-8000-000000000004", "generate-text");
    let service =
        ConversationTextService::new(store.clone(), store.clone(), authority, available_guard());
    let original = BeginConversationTextInput {
        conversation_id,
        expected_version: 1,
        text: MessageText::new("hello").unwrap(),
    };
    let started = service
        .begin(&generation_context, original.clone())
        .unwrap();
    assert_eq!(started.phase, TextGenerationPhase::Started);
    let lineage = rusqlite::Connection::open(&database_path)
        .unwrap()
        .query_row(
            "SELECT workspace_id, classification, origin_operation
             FROM task_run_workspace_lineage WHERE taskrun_id = ?1",
            [started.taskrun_id.as_bytes()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        lineage,
        (workspace_id.as_bytes().to_vec(), "canonical".into(), 18)
    );
    rusqlite::Connection::open(&database_path)
        .unwrap()
        .execute(
            "UPDATE workspaces SET live = 0 WHERE workspace_id = ?1",
            [workspace_id.as_bytes()],
        )
        .unwrap();
    let project_version: u64 = projects
        .get_project("local-owner", project_id)
        .unwrap()
        .version();
    assert!(
        projects
            .delete_project(
                "local-owner",
                "018f2e3a-7000-7000-8000-000000000013".parse().unwrap(),
                &IdempotencyKey::new("delete-running").unwrap(),
                project_id,
                project_version,
            )
            .is_err()
    );
    let rejected_input = FinishConversationTextInput {
        original,
        started: started.clone(),
        completion: ConversationTextCompletion::Rejected {
            reason: GenerationFailureReason::ProviderOutputRejected,
        },
    };

    let rejected = service
        .finish(&generation_context, rejected_input.clone())
        .unwrap();
    let snapshots_before: SnapshotState = rusqlite::Connection::open(&database_path)
        .unwrap()
        .prepare(
            "SELECT aggregate_type, projection_bytes, projection_digest, snapshot_integrity_digest
         FROM aggregate_state_snapshots ORDER BY aggregate_type",
        )
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let duplicate = service
        .finish(&generation_context, rejected_input.clone())
        .unwrap();

    assert_eq!(rejected, duplicate);
    assert_eq!(rejected.phase, TextGenerationPhase::Rejected);
    assert_eq!(rejected.conversation_version, 3);
    assert_eq!(rejected.taskrun_version, 5);
    let snapshots_after: SnapshotState = rusqlite::Connection::open(&database_path)
        .unwrap()
        .prepare(
            "SELECT aggregate_type, projection_bytes, projection_digest, snapshot_integrity_digest
         FROM aggregate_state_snapshots ORDER BY aggregate_type",
        )
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(snapshots_before, snapshots_after);
    let mut invalid = rejected.clone();
    invalid.phase = TextGenerationPhase::Started;
    let connection = rusqlite::Connection::open(&database_path).unwrap();
    connection
        .execute(
            "UPDATE command_receipts SET command_outcome = ?1 WHERE command_id = ?2",
            rusqlite::params![
                TextGenerationReceiptCodec.encode(&invalid).unwrap(),
                generation_context.command_id.as_bytes()
            ],
        )
        .unwrap();
    assert_eq!(
        projects.delete_project(
            "local-owner",
            "018f2e3a-7000-7000-8000-000000000015".parse().unwrap(),
            &IdempotencyKey::new("delete-invalid-text-origin").unwrap(),
            project_id,
            project_version,
        ),
        Err(gocode_application::ports::ProjectWorkspaceRepositoryError::InvariantViolation)
    );
    connection
        .execute(
            "UPDATE command_receipts SET command_outcome = ?1 WHERE command_id = ?2",
            rusqlite::params![
                TextGenerationReceiptCodec.encode(&rejected).unwrap(),
                generation_context.command_id.as_bytes()
            ],
        )
        .unwrap();
    assert_eq!(
        projects
            .delete_project(
                "local-owner",
                "018f2e3a-7000-7000-8000-000000000014".parse().unwrap(),
                &IdempotencyKey::new("delete-terminal").unwrap(),
                project_id,
                project_version,
            )
            .unwrap(),
        4
    );

    let conversation_stream = store.load_conversation(conversation_id).unwrap();
    assert_eq!(conversation_stream.current_version, 3);
    let conversation = Conversation::replay(&conversation_stream.events).unwrap();
    assert_eq!(conversation.messages().len(), 1);
    assert_eq!(conversation.active_generation(), None);

    let taskrun_stream = store.load_task_run(rejected.taskrun_id).unwrap();
    assert_eq!(taskrun_stream.current_version, 5);
    assert!(matches!(
        taskrun_stream.events.last().unwrap().payload(),
        TaskRunEvent::TaskRunFailed { reason } if reason == "provider_output_rejected"
    ));
    let taskrun = TaskRun::replay(&taskrun_stream.events).unwrap();
    assert_eq!(taskrun.state(), TaskRunState::Failed);
    assert_eq!(taskrun.active_attempt(), None);

    let lineage_connection = rusqlite::Connection::open(&database_path).unwrap();
    lineage_connection
        .execute(
            "UPDATE task_run_workspace_lineage SET origin_operation = 1
             WHERE taskrun_id = ?1",
            [rejected.taskrun_id.as_bytes()],
        )
        .unwrap();
    assert_eq!(
        service.finish(&generation_context, rejected_input.clone()),
        Err(ConversationTextServiceError::Commit(
            CommitError::StorageFailure(StorageFailureKind::IntegrityViolation)
        ))
    );
    lineage_connection
        .execute(
            "UPDATE task_run_workspace_lineage SET origin_operation = 18
             WHERE taskrun_id = ?1",
            [rejected.taskrun_id.as_bytes()],
        )
        .unwrap();
    rusqlite::Connection::open(&database_path)
        .unwrap()
        .execute(
            "DELETE FROM task_run_workspace_lineage WHERE taskrun_id = ?1",
            [rejected.taskrun_id.as_bytes()],
        )
        .unwrap();
    assert_eq!(
        service.finish(&generation_context, rejected_input),
        Err(ConversationTextServiceError::Commit(
            CommitError::StorageFailure(StorageFailureKind::IntegrityViolation)
        ))
    );
}
