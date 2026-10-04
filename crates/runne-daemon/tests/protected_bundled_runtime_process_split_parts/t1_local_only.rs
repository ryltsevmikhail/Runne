use super::t1_taskrun_support::LocalTaskRunContext;

pub(super) async fn exercise_if_requested(mut context: LocalTaskRunContext<'_>) {
    if std::env::var_os("RUNNE_TEST_T1_LOCAL_CRASH_ONLY").is_some() {
        super::t1_local_crash_recovery::exercise_daemon_crash_recovery(&mut context).await;
        return;
    }
    if super::t1_local_barrier::exercise_if_requested(&mut context).await {
        context
            .supervisor
            .stop()
            .expect("stop daemon after local barrier scenario");
        return;
    }
    super::t1_local_commands::exercise_local_commands(
        &context.client,
        context.conversation_id,
        context.workspace_id,
        context.project_directory,
        context.database,
        context.runtime_root,
    )
    .await;
    super::t1_local_cancel::exercise_running_cancel(
        &context.client,
        context.conversation_id,
        context.workspace_id,
        context.project_directory,
        context.database,
    )
    .await;
    let (recovered_client, mut recovered_supervisor) =
        super::t1_local_restart_cancel::exercise_restart_during_local_cancel(
            context,
            std::env::var_os("RUNNE_TEST_T1_LOCAL_MISSING_AREA").is_some(),
        )
        .await;
    drop(recovered_client);
    recovered_supervisor
        .stop()
        .expect("stop daemon after cancellation restart test");
}
