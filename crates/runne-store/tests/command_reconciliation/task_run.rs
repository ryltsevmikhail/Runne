use super::*;

use runne_application::commands::{
    AdmitTaskRunInput, CancelTaskRunInput, CommandOutcome, CreateTaskRunInput, QueueTaskRunInput,
    SubmitTaskRunInput,
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

#[test]
fn task_run_submit_is_reconciled_from_the_authoritative_receipt() {
    let fixture = Fixture::new("command-reconciliation-task-run-submit");
    fixture.project_workspace();
    let task_service = TaskRunService::new(
        fixture.store.clone(),
        fixture.store.clone(),
        fixture.store.clone(),
        RuntimeAuthorityId("authority".into()),
    );
    let submitted = task_service
        .submit_task_run(
            &application_context(command(11), "key"),
            SubmitTaskRunInput {
                conversation_id: conversation(),
                workspace_id: workspace(),
            },
        )
        .unwrap();
    assert!(matches!(
        submitted,
        CommandOutcome::TaskRunSubmitted {
            taskrun_id: submitted_id,
            new_version: 2,
        } if submitted_id != taskrun_zero()
    ));

    let witness = CommandReconciliationWitness::submit_task_run(conversation(), workspace());
    assert!(matches!(
        fixture
            .repository
            .reconcile_command(&context(command(11)), &witness),
        Ok(CommandReconciliationEvidence::Terminal(_))
    ));

    let other_workspace: runne_domain::id::WorkspaceId =
        "018f47a2-4f8c-7b52-8c35-7a3a14c2d913".parse().unwrap();
    let changed = CommandReconciliationWitness::submit_task_run(conversation(), other_workspace);
    assert!(matches!(
        fixture
            .repository
            .reconcile_command(&context(command(11)), &changed),
        Err(CommandReconciliationRepositoryError::Conflict)
    ));

    let unseen = CommandReconciliationWitness::submit_task_run(conversation(), workspace());
    let unseen_context = CommandReconciliationContext::new(
        command(12),
        IdempotencyKey::new("unseen-submit-key").unwrap(),
        ApiPrincipalId::new("owner").unwrap(),
    );
    assert!(matches!(
        fixture
            .repository
            .reconcile_command(&unseen_context, &unseen),
        Ok(CommandReconciliationEvidence::NotCommitted)
    ));
}

fn taskrun_zero() -> runne_domain::id::TaskRunId {
    "00000000-0000-7000-8000-000000000000".parse().unwrap()
}
