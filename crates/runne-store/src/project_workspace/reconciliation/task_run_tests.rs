use super::*;
use runne_domain::id::TaskRunId;

const TASK_RUN: &str = "018f2e3a-7000-7000-8000-000000000304";

#[test]
fn cancellation_receipt_correlates_to_the_expected_task_run_version() {
    let task_run: TaskRunId = TASK_RUN.parse().unwrap();
    let witness = CommandReconciliationWitness::cancel_task_run(task_run, 4);
    let outcome = outcome_for(
        None,
        &witness,
        CommandOutcome::TaskRunCancellationRequested {
            taskrun_id: task_run,
            new_version: 5,
        },
    )
    .unwrap();

    assert_eq!(
        outcome,
        AuthoritativeCommandOutcome::task_run_cancellation_requested(
            runne_api::TaskRunCommandAck {
                taskrun_id: task_run,
                new_version: 5,
                kind: runne_api::TaskRunCommandAckKind::CancellationRequested,
            },
        )
    );
}
