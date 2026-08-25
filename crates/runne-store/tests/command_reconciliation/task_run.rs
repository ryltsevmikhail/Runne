use super::*;

use runne_application::commands::{
    AdmitTaskRunInput, CancelTaskRunInput, CommandOutcome, CreateTaskRunInput, QueueTaskRunInput,
};
use runne_application::service::TaskRunService;

#[test]
fn task_run_cancellation_is_reconciled_from_the_authoritative_receipt() {
    let fixture = Fixture::new("command-reconciliation-task-run");
    fixture.project_workspace();
    let task_service = TaskRunService::new(
        fixture.store.clone(),
        fixture.store.clone(),
        fixture.store.clone(),
        RuntimeAuthorityId("authority".into()),
    );
    let created = task_service
        .create_task_run(
            &application_context(command(7), "create-task-run"),
            CreateTaskRunInput {
                conversation_id: conversation(),
                workspace_id: workspace(),
            },
        )
        .unwrap();
    let CommandOutcome::TaskRunCreated { taskrun_id, .. } = created else {
        panic!("expected task run creation")
    };
    task_service
        .queue_task_run(
            &application_context(command(8), "queue-task-run"),
            QueueTaskRunInput {
                taskrun_id,
                expected_version: 1,
            },
        )
        .unwrap();
    task_service
        .admit_task_run(
            &application_context(command(9), "admit-task-run"),
            AdmitTaskRunInput {
                taskrun_id,
                expected_version: 2,
            },
        )
        .unwrap();
    let cancelled = task_service
        .cancel_task_run(
            &application_context(command(10), "key"),
            CancelTaskRunInput {
                taskrun_id,
                expected_version: 3,
            },
        )
        .unwrap();
    assert!(matches!(
        cancelled,
        CommandOutcome::TaskRunCancellationRequested {
            taskrun_id: cancelled_id,
            new_version: 4,
        } if cancelled_id == taskrun_id
    ));

    let witness = CommandReconciliationWitness::cancel_task_run(taskrun_id, 3);
    assert!(matches!(
        fixture
            .repository
            .reconcile_command(&context(command(10)), &witness),
        Ok(CommandReconciliationEvidence::Terminal(_))
    ));
}
