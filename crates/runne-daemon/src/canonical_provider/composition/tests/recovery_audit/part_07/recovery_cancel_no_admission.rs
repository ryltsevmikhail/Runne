#[path = "recovery_cancel_no_admission/support.rs"]
mod support;
use support::{create_cancelled_no_admission, provider_effect_counts};

#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
#[tokio::test(flavor = "current_thread")]
async fn startup_closes_canonical_cancelled_no_admission_and_replays_after_reopen() {
    let case = create_cancelled_no_admission(1).await;
    let before = provider_effect_counts(&case.harness.query_connection());
    case.assert_no_provider_effects();
    let worker = crate::application::exec_taskrun_recovery::provider_only_taskrun_service_for_test(
        case.harness.store.clone(),
        case.tasks(),
        case.harness.text_service(),
        Some(case.provider.clone()),
        case.node_bytes,
        case.harness.generation(),
        Arc::new(AtomicU64::new(case.harness.generation())),
    )
    .unwrap();
    drop(worker);
    case.assert_closed(&before);
    let closed = case.closed_snapshot();

    let reopened = case.reopen_store();
    let reopened_text = case.reopened_text(&reopened);
    let repeated =
        crate::application::exec_taskrun_recovery::provider_only_taskrun_service_for_test(
            reopened.clone(),
            case.tasks_for(&reopened),
            reopened_text,
            None,
            case.node_bytes,
            case.harness.generation(),
            Arc::new(AtomicU64::new(case.harness.generation())),
        )
        .unwrap();
    drop(repeated);
    case.assert_reopened_unchanged(&reopened, &closed);
}

#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
#[tokio::test(flavor = "current_thread")]
async fn live_cancellation_route_closes_no_admission_without_provider_effects() {
    let case = create_cancelled_no_admission(2).await;
    let before = provider_effect_counts(&case.harness.query_connection());
    case.assert_no_provider_effects();
    let worker = crate::application::exec_taskrun_worker::DaemonAutomaticTaskRuns::new(
        case.harness.store.clone(),
        case.tasks(),
        case.harness.text_service(),
        Some(case.provider.clone()),
        runne_application::ports::ExecutionNodeId(
            uuid::Uuid::from_bytes(case.node_bytes).to_string(),
        ),
        case.harness.generation(),
        Arc::new(AtomicU64::new(case.harness.generation())),
    );
    runne_runtime::taskrun_auto_worker::AutomaticTaskRunService::complete_queued_cancellation(
        &worker,
        case.taskrun_id,
        case.cancellation_version,
    )
    .await
    .unwrap();
    case.assert_closed(&before);
    let closed = case.closed_snapshot();
    let reopened = case.reopen_store();
    case.assert_reopened_unchanged(&reopened, &closed);
}

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
