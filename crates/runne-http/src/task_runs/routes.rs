use super::*;

/// Builds the authority TaskRun route set; client profiles mount only the
/// canonical client subset.
pub fn task_run_router<H>(state: TaskRunHttpState<H>) -> Router
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort + 'static,
{
    Router::new()
        .route(
            "/v1/task-runs",
            get(list_task_runs::<H>).post(create_task_run::<H>),
        )
        .route("/v1/task-runs/submit", post(submit_task_run_v1::<H>))
        .route("/v1/task-runs/{taskrun_id}", get(get_task_run::<H>))
        .route(
            "/v1/task-runs/{taskrun_id}/effects",
            get(get_task_run_effects::<H>),
        )
        .route(
            "/v1/task-runs/{taskrun_id}/queue",
            post(queue_task_run::<H>),
        )
        .route(
            "/v1/task-runs/{taskrun_id}/admit",
            post(admit_task_run::<H>),
        )
        .route(
            "/v1/task-runs/{taskrun_id}/cancel",
            post(cancel_task_run::<H>),
        )
        .route(
            "/v1/task-runs/{taskrun_id}/successor",
            post(supersede_unknown_task_run::<H>),
        )
        .route(
            "/v1/task-runs/{taskrun_id}/attempts",
            post(start_attempt::<H>),
        )
        .route(
            "/v1/task-runs/{taskrun_id}/complete",
            post(complete_task_run::<H>),
        )
        .layer(DefaultBodyLimit::max(MAX_TASK_RUN_BODY_BYTES))
        .with_state(state)
}
