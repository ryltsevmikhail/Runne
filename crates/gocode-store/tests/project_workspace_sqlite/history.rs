use gocode_application::commands::CreateTaskRunInput;
use gocode_application::errors::ApplicationError;
use gocode_application::ports::{
    ProjectWorkspaceRepository, ProjectWorkspaceRepositoryError as Error, StorageFailureKind,
};
use gocode_domain::id::{ConversationId, WorkspaceId};

use super::fence::create_task_run;
use super::support::*;

#[test]
fn workspace_identity_history_prevents_rebind_after_mutable_row_loss() {
    let database = Database::new("pw-workspace-history-rebind");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);

    let connection = database.connection();
    let history = connection
        .query_row(
            "SELECT project_id, principal_id, classification
             FROM workspace_identity_history WHERE workspace_id = ?1",
            [WORKSPACE],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .unwrap();
    assert_eq!(
        history,
        (PROJECT.to_vec(), "owner".into(), "canonical".into())
    );

    connection
        .execute(
            "DELETE FROM workspaces WHERE workspace_id = ?1",
            [WORKSPACE],
        )
        .unwrap();
    assert_eq!(
        repository.create_workspace(
            "owner",
            command(0x58),
            &key("rebind-deleted-workspace"),
            workspace(WORKSPACE, PROJECT, "Rebound"),
        ),
        Err(Error::Conflict)
    );
}

#[test]
fn legacy_unbound_workspace_history_cannot_be_claimed_by_a_project() {
    let database = Database::new("pw-legacy-history-rebind");
    let repository = database.repository();
    create_project(&repository);
    let workspace_id = command(0x57).into_bytes();
    database
        .connection()
        .execute(
            "INSERT INTO workspace_identity_history
             (workspace_id, project_id, principal_id, classification)
             VALUES (?1, NULL, NULL, 'legacy_unbound')",
            [workspace_id],
        )
        .unwrap();

    assert_eq!(
        repository.create_workspace(
            "owner",
            command(0x56),
            &key("claim-legacy-workspace"),
            workspace(workspace_id, PROJECT, "Claimed legacy workspace"),
        ),
        Err(Error::Conflict)
    );
}

#[test]
fn canonical_taskrun_origin_rejects_missing_workspace_history() {
    let database = Database::new("pw-missing-workspace-history");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    database
        .connection()
        .execute(
            "DELETE FROM workspace_identity_history WHERE workspace_id = ?1",
            [WORKSPACE],
        )
        .unwrap();

    let result = database.task_runs().create_task_run(
        &task_context(0x59, "missing-history-origin"),
        CreateTaskRunInput {
            conversation_id: ConversationId::from_bytes(command(0x5a).into_bytes()),
            workspace_id: WorkspaceId::from_bytes(WORKSPACE),
        },
    );
    assert_eq!(
        result,
        Err(ApplicationError::StorageFailed(
            StorageFailureKind::IntegrityViolation
        ))
    );
}

#[test]
fn canonical_taskrun_origin_rejects_mismatched_workspace_history() {
    let database = Database::new("pw-mismatched-workspace-history");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    database
        .connection()
        .execute(
            "UPDATE workspace_identity_history SET project_id = ?1
             WHERE workspace_id = ?2",
            rusqlite::params![PROJECT_2, WORKSPACE],
        )
        .unwrap();

    let result = database.task_runs().create_task_run(
        &task_context(0x5b, "mismatched-history-origin"),
        CreateTaskRunInput {
            conversation_id: ConversationId::from_bytes(command(0x5c).into_bytes()),
            workspace_id: WorkspaceId::from_bytes(WORKSPACE),
        },
    );
    assert_eq!(
        result,
        Err(ApplicationError::StorageFailed(
            StorageFailureKind::IntegrityViolation
        ))
    );
}

#[test]
fn delete_audit_rejects_lineage_without_immutable_workspace_history() {
    let database = Database::new("pw-delete-missing-workspace-history");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    create_task_run(&database, 0x5d);
    let connection = database.connection();
    connection
        .execute(
            "UPDATE workspaces SET live = 0 WHERE workspace_id = ?1",
            [WORKSPACE],
        )
        .unwrap();
    connection
        .execute(
            "DELETE FROM workspace_identity_history WHERE workspace_id = ?1",
            [WORKSPACE],
        )
        .unwrap();

    assert_eq!(
        repository.delete_project(
            "owner",
            command(0x5e),
            &key("delete-missing-history"),
            gocode_domain::id::ProjectId::from_bytes(PROJECT),
            1,
        ),
        Err(Error::InvariantViolation)
    );
}
