use gocode_application::ports::{
    AggregateScope, IdempotencyScope, OperationTag, PrincipalId, ProjectWorkspaceRepository,
    ProjectWorkspaceRepositoryError as Error,
};
use gocode_domain::id::ProjectId;
use gocode_store::codec::{IdempotencyScopeCodec, StoreCodec};

use super::integrity::eligible_project;
use super::support::*;

#[test]
fn direct_origin_rejects_operation_inconsistent_aggregate_shape() {
    let database = Database::new("pw-direct-origin-aggregate-shape");
    let taskrun_id = eligible_project(&database, 64);
    let invalid = IdempotencyScope {
        runtime_authority_id: authority(),
        principal_id: PrincipalId("owner".into()),
        operation: OperationTag::CreateTaskRun,
        aggregate_scope: AggregateScope::ExistingTaskRun { taskrun_id },
    };
    database
        .connection()
        .execute(
            "UPDATE command_receipts SET idempotency_scope_bytes = ?1
             WHERE command_id = ?2",
            rusqlite::params![
                IdempotencyScopeCodec.encode(&invalid).unwrap(),
                command(64).as_bytes()
            ],
        )
        .unwrap();
    assert_eq!(
        database.repository().delete_project(
            "owner",
            command(65),
            &key("delete-wrong-origin-scope"),
            ProjectId::from_bytes(PROJECT),
            1,
        ),
        Err(Error::InvariantViolation)
    );
}

#[test]
fn direct_duplicate_lookup_rejects_corrupt_lineage_mapping() {
    let database = Database::new("pw-direct-duplicate-corrupt-lineage");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let taskrun_id = super::fence::create_task_run(&database, 66);
    database
        .connection()
        .execute(
            "UPDATE task_run_workspace_lineage SET origin_operation = 18
             WHERE taskrun_id = ?1",
            [taskrun_id.as_bytes()],
        )
        .unwrap();
    assert!(
        database
            .task_runs()
            .create_task_run(
                &task_context(66, "task-create"),
                gocode_application::commands::CreateTaskRunInput {
                    conversation_id: gocode_domain::id::ConversationId::from_bytes(
                        command(0x31).into_bytes(),
                    ),
                    workspace_id: gocode_domain::id::WorkspaceId::from_bytes(WORKSPACE),
                },
            )
            .is_err()
    );
}
