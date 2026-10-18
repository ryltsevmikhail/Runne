use super::*;

#[path = "full_access_live_downgrade/phases/downgrade_stale_denial.rs"]
mod downgrade_stale_denial;
#[path = "full_access_live_downgrade/receipts.rs"]
mod receipts;
#[path = "full_access_live_downgrade/phases/run_and_rebind.rs"]
mod run_and_rebind;

use receipts::*;

#[expect(
    clippy::too_many_arguments,
    reason = "The fixture needs the exact runtime root, public client, and same-root restart handles."
)]
pub(super) async fn exercise(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    conversation_id: runne_runtime_client::CanonicalId,
    workspace_id: runne_runtime_client::CanonicalId,
    project_directory: &Path,
    database: &Path,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    executable: &Path,
    session_bus_socket: &Path,
    runtime_root: &Path,
) {
    let (mut reopened, reopened_client, listener, started, late, next_revision) =
        run_and_rebind::run(
            client,
            conversation_id,
            workspace_id,
            project_directory,
            database,
            supervisor,
            executable,
            session_bus_socket,
            runtime_root,
        )
        .await;
    downgrade_stale_denial::run(
        &mut reopened,
        &reopened_client,
        conversation_id,
        workspace_id,
        project_directory,
        database,
        executable,
        session_bus_socket,
        runtime_root,
        listener,
        &started,
        &late,
        next_revision,
    )
    .await;
}
