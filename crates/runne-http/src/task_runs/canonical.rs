/// Builds the client-facing canonical TaskRun surface.
///
/// Clients see exactly submit/list/get/cancel. Runtime-owned transitions
/// (create, queue, admit, attempt start, completion) stay on the authority
/// router and are never mounted for a profile without separate internal
/// authority.
pub fn canonical_task_run_router<H>(state: TaskRunHttpState<H>) -> Router
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort + 'static,
{
    Router::new()
        .route("/v1/task-runs", get(list_task_runs::<H>))
        .route("/v1/task-runs/submit", post(submit_task_run::<H>))
        .route("/v1/task-runs/{taskrun_id}", get(get_task_run::<H>))
        .route(
            "/v1/task-runs/{taskrun_id}/cancel",
            post(cancel_task_run::<H>),
        )
        .layer(DefaultBodyLimit::max(MAX_TASK_RUN_BODY_BYTES))
        .with_state(state)
}
