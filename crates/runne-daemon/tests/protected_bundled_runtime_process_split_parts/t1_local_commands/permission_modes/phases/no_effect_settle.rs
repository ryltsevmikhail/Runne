use std::path::Path;

use super::*;

#[expect(
    clippy::too_many_arguments,
    reason = "The settle phase keeps the client, supervisor, listener, and TaskRun handles together."
)]
pub(super) async fn run(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    conversation_id: runne_runtime_client::CanonicalId,
    workspace_id: runne_runtime_client::CanonicalId,
    project_directory: &Path,
    database: &Path,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    mode: runne_api::PermissionModeV1,
    allows_network: bool,
    task: runne_runtime_client::CanonicalId,
    payload: &str,
    listener: LoopbackCapture,
    selected_authorization_revision: u64,
) -> (
    Option<LocalNoEffectCase>,
    Option<LocalNoEffectCase>,
    Option<LocalNoEffectCase>,
    Option<(runne_runtime_client::CanonicalId, u64, std::path::PathBuf)>,
    runne_api::PermissionModeStatusV1,
) {
    let payloads = listener.finish();
    assert_eq!(
        payloads,
        if allows_network {
            vec![format!("{payload}\n").into_bytes()]
        } else {
            vec![]
        }
    );
    assert_no_task_approval(client, task).await;
    let denied = if mode != runne_api::PermissionModeV1::FullAccess {
        Some(
            exercise_local_no_effect_case(
                client,
                conversation_id,
                workspace_id,
                project_directory,
                database,
                LocalNoEffectResolution::Deny,
            )
            .await,
        )
    } else {
        None
    };
    let expired = if mode == runne_api::PermissionModeV1::AskAlways {
        Some(
            exercise_local_no_effect_case(
                client,
                conversation_id,
                workspace_id,
                project_directory,
                database,
                LocalNoEffectResolution::Expire,
            )
            .await,
        )
    } else {
        None
    };
    let mode_changed = if mode == runne_api::PermissionModeV1::RiskBased {
        Some(
            exercise_local_no_effect_case(
                client,
                conversation_id,
                workspace_id,
                project_directory,
                database,
                LocalNoEffectResolution::ChangeMode(&mut *supervisor),
            )
            .await,
        )
    } else {
        None
    };
    let revoke = if allows_network {
        Some(
            exercise_full_access_trust_revoke(
                client,
                conversation_id,
                workspace_id,
                project_directory,
                database,
            )
            .await,
        )
    } else {
        None
    };

    let expected_mode = if mode_changed.is_some() {
        runne_api::PermissionModeV1::AskAlways
    } else {
        mode
    };
    let final_mode = client
        .permission_mode_status(workspace_id)
        .await
        .expect("read final permission mode before same-root reopen");
    assert_eq!(final_mode.selected_mode, expected_mode);
    assert_eq!(
        final_mode.authorization_revision,
        selected_authorization_revision + if mode_changed.is_some() { 1 } else { 0 }
    );

    supervisor
        .stop()
        .expect("stop exact local permission-mode daemon for same-root reopen");

    (denied, expired, mode_changed, revoke, final_mode)
}
