use super::*;

#[path = "t1_local_crash_recovery_parts/phases/fresh_claim_rejection.rs"]
mod fresh_claim_rejection;
#[path = "t1_local_crash_recovery_parts/native_state.rs"]
mod native_state;
#[path = "t1_local_crash_recovery_parts/phases/restart_recovery.rs"]
mod restart_recovery;
#[path = "t1_local_crash_recovery_parts/phases/submit_and_kill.rs"]
mod submit_and_kill;

use native_state::*;

pub(super) async fn exercise_daemon_crash_recovery(
    context: &mut super::t1_taskrun_support::LocalTaskRunContext<'_>,
    expected_permission_mode: Option<runne_api::PermissionModeV1>,
) {
    let client = &context.client;
    let conversation_id = context.conversation_id;
    let workspace_id = context.workspace_id;
    let project_directory = context.project_directory;
    let database = context.database;
    let runtime_root = context.runtime_root;
    let executable = context.executable;
    let supervisor = &mut *context.supervisor;
    let (permission_before, task_run_id, task_bytes, marker, detached, restarted, restarted_client) =
        submit_and_kill::run(
            client,
            conversation_id,
            workspace_id,
            project_directory,
            database,
            runtime_root,
            executable,
            supervisor,
            expected_permission_mode,
        )
        .await;
    let (runtime_authority_id, store, node_id, node_epoch, terminal_version) =
        restart_recovery::run(
            workspace_id,
            database,
            &marker,
            &detached,
            permission_before,
            task_run_id,
            task_bytes,
            restarted,
            restarted_client,
        )
        .await;
    fresh_claim_rejection::run(
        database,
        task_bytes,
        &store,
        runtime_authority_id,
        node_id,
        node_epoch,
        terminal_version,
    )
    .await;
}
