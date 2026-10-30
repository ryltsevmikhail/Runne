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
        .route(
            "/v1/task-runs/{taskrun_id}/tools",
            get(get_task_run_tool_activity::<H>),
        )
        .route("/v1/task-runs", get(list_task_runs::<H>))
        .route("/v1/task-runs/submit", post(submit_task_run_v1::<H>))
        .route("/v1/task-runs/{taskrun_id}", get(get_task_run::<H>))
        .route(
            "/v1/task-runs/{taskrun_id}/effects",
            get(get_task_run_effects::<H>),
        )
        .route(
            "/v1/task-runs/{taskrun_id}/cancel",
            post(cancel_task_run::<H>),
        )
        .route(
            "/v1/task-runs/{taskrun_id}/successor",
            post(supersede_unknown_task_run::<H>),
        )
        .layer(DefaultBodyLimit::max(MAX_TASK_RUN_BODY_BYTES))
        .with_state(state)
}

/// Builds the v2 prompted submit route. Callers mount this only when their
/// runtime profile advertises `task_run.submit.v2`.
pub(crate) fn prompted_task_run_router<H>(state: TaskRunHttpState<H>) -> Router
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort + 'static,
{
    Router::new()
        .route(
            "/v2/task-runs/submit",
            post(submit_task_run_v2::<H>)
                .layer(DefaultBodyLimit::max(MAX_TASK_RUN_SUBMIT_BODY_BYTES)),
        )
        .with_state(state)
}

pub(crate) fn mount_prompted_submit_for_profile<H>(
    router: Router,
    state: TaskRunHttpState<H>,
    profile: &crate::runtime_profile::RuntimeProfileHttpState,
) -> Router
where
    H: TaskRunCommandHostPort + TaskRunQueryHostPort + 'static,
{
    if profile.advertises("task_run.submit.v2") {
        router.merge(prompted_task_run_router(state))
    } else {
        router
    }
}
