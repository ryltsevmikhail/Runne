use std::sync::Arc;

use runne_application::commands::CancelTaskRunInput;
use runne_application::ports::{EventStore, TaskRunAssignmentIdentity};
use runne_application::service::TaskRunService;
use runne_domain::task_run::{SelectedProviderProfile, TaskRun, TaskRunState};
use runne_runtime::canonical_provider_execution::{
    CanonicalProviderExecutionJob, CanonicalProviderExecutionService,
};
use runne_store::provider::ProviderDispatchState;

use super::super::super::recovery_audit::Harness;
use super::super::DaemonCanonicalProviderService;
use super::PausedEffect;
use super::test_context;

pub(super) async fn assert_cancellation_denies_before_send(
    harness: &Harness,
    service: &Arc<DaemonCanonicalProviderService>,
    job: CanonicalProviderExecutionJob,
    assignment: Option<TaskRunAssignmentIdentity>,
    selected: Option<SelectedProviderProfile>,
    effect: Arc<PausedEffect>,
) {
    let taskrun_id = job.started.taskrun_id;
    let version = job.started.taskrun_version;
    let entered = effect.entered.notified();
    tokio::pin!(entered);
    let execution = Arc::clone(service);
    let task = tokio::spawn(async move {
        match assignment {
            Some(assignment) => {
                execution
                    .execute_claimed_selected_profile(job, assignment, selected)
                    .await
            }
            None => execution.execute(job).await,
        }
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), &mut entered)
        .await
        .expect("adapter pre-consume barrier");
    let cancellation = TaskRunService::new(
        harness.store.clone(),
        harness.store.clone(),
        harness.store.clone(),
        harness.authority(),
    )
    .cancel_task_run(
        &test_context(0xBE, 0x01, "preconsume-cancel"),
        CancelTaskRunInput {
            taskrun_id,
            expected_version: version,
        },
    )
    .unwrap();
    effect.release.add_permits(1);
    let result = task.await.unwrap();
    assert_eq!(
        result,
        Err(crate::canonical_provider::CanonicalProviderExecutionError::Uncertain)
    );
    assert_eq!(effect.consumes.load(super::Ordering::SeqCst), 1);
    assert_eq!(effect.sends.load(super::Ordering::SeqCst), 0);
    assert!(matches!(
        cancellation,
        runne_application::commands::CommandOutcome::TaskRunCancellationRequested {
            new_version: 5,
            ..
        }
    ));
    assert_eq!(
        TaskRun::replay(&harness.store.load_task_run(taskrun_id).unwrap().events)
            .unwrap()
            .state(),
        TaskRunState::Cancelling
    );
    let attempt = effect.attempt.lock().unwrap().unwrap();
    assert_eq!(
        service
            .dispatch_store
            .get_dispatch(attempt)
            .unwrap()
            .unwrap()
            .state,
        ProviderDispatchState::Uncertain
    );
}
