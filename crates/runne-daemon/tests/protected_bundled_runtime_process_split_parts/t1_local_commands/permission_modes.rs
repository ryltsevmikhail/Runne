use std::{path::Path, time::Duration};

use super::super::t1_local_only::{LoopbackCapture, wait_for_file};

#[path = "full_access_live_downgrade.rs"]
mod full_access_live_downgrade;
#[path = "legacy_selection.rs"]
mod legacy_selection;
#[path = "network_matrix.rs"]
mod network_matrix;
#[path = "path_process_matrix.rs"]
mod path_process_matrix;
#[path = "shell_corpus.rs"]
mod shell_corpus;
#[path = "unavailable_network.rs"]
mod unavailable_network;

#[path = "permission_modes/approval_flow.rs"]
mod approval_flow;
#[path = "permission_modes/facts.rs"]
mod facts;
#[path = "permission_modes/filesystem_matrix.rs"]
pub(crate) mod filesystem_matrix;
#[path = "permission_modes/phases/matrix_run.rs"]
mod matrix_run;
#[path = "permission_modes/no_effect_cases.rs"]
mod no_effect_cases;
#[path = "permission_modes/phases/no_effect_settle.rs"]
mod no_effect_settle;
#[path = "permission_modes/precapture.rs"]
mod precapture;
#[path = "permission_modes/phases/reopened_revoke.rs"]
mod reopened_revoke;
#[path = "permission_modes/trust_revoke.rs"]
mod trust_revoke;

use approval_flow::*;
use facts::*;
use filesystem_matrix::*;
use no_effect_cases::*;
use trust_revoke::*;

#[expect(
    clippy::too_many_arguments,
    reason = "Fixture plumbing keeps the exact native process, authority, barrier, and filesystem handles together."
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
    mode: runne_api::PermissionModeV1,
) {
    if std::env::var_os("RUNNE_TEST_T1_LOCAL_UNAVAILABLE_NETWORK").is_some() {
        assert_eq!(mode, runne_api::PermissionModeV1::FullAccess);
        unavailable_network::exercise(
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
        return;
    }
    if std::env::var_os("RUNNE_TEST_T1_LOCAL_LEGACY_SELECTION").as_deref()
        == Some(std::ffi::OsStr::new("1"))
    {
        assert_eq!(mode, runne_api::PermissionModeV1::RiskBased);
        legacy_selection::exercise(
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
        return;
    }
    if std::env::var_os("RUNNE_TEST_T1_LOCAL_FULL_ACCESS_LIVE_DOWNGRADE").is_some() {
        assert_eq!(mode, runne_api::PermissionModeV1::FullAccess);
        full_access_live_downgrade::exercise(
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
        return;
    }
    eprintln!("RUN: real local-command X2 effects for {mode:?}");
    let selected_mode = client
        .permission_mode_status(workspace_id)
        .await
        .expect("read selected permission mode before local TaskRuns");
    assert_eq!(selected_mode.selected_mode, mode);
    if let Ok(case) = std::env::var("RUNNE_TEST_T1_LOCAL_PRECAPTURE_FAILURE_CASE") {
        assert_eq!(mode, runne_api::PermissionModeV1::AskAlways);
        precapture::exercise_precapture_failure(
            client,
            conversation_id,
            workspace_id,
            project_directory,
            database,
            supervisor,
            executable,
            session_bus_socket,
            runtime_root,
            &case,
            selected_mode.authorization_revision,
        )
        .await;
        return;
    }
    let (
        listener,
        filesystem,
        path_process,
        shell_corpus,
        network,
        before_network,
        after_network,
        payload,
        request,
        changed_intents,
        task,
        terminal,
        local_facts,
        allows_network,
    ) = matrix_run::run(
        client,
        conversation_id,
        workspace_id,
        project_directory,
        database,
        mode,
    )
    .await;
    let (denied, expired, mode_changed, revoke, final_mode) = no_effect_settle::run(
        client,
        conversation_id,
        workspace_id,
        project_directory,
        database,
        supervisor,
        mode,
        allows_network,
        task,
        &payload,
        listener,
        selected_mode.authorization_revision,
    )
    .await;
    reopened_revoke::run(
        executable,
        session_bus_socket,
        runtime_root,
        workspace_id,
        database,
        mode,
        allows_network,
        &final_mode,
        task,
        &request,
        &changed_intents,
        &payload,
        &before_network,
        &after_network,
        &filesystem,
        &path_process,
        &shell_corpus,
        network,
        &terminal,
        local_facts,
        denied,
        expired,
        mode_changed,
        revoke,
    )
    .await;
}
