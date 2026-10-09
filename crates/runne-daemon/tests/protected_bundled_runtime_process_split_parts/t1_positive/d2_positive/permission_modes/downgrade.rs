use super::CommittedModeSelection;

#[path = "downgrade/assertions.rs"]
mod assertions;
use assertions::*;

pub(in crate::t1_positive::d2_pending) fn active_downgrade_barrier() -> Option<&'static str> {
    if !matches!(
        std::env::var("RUNNE_TEST_D2_PERMISSION_MODE").as_deref(),
        Ok("full_access")
    ) {
        return None;
    }
    let scenario = std::env::var("RUNNE_TEST_D2_TOOL_SCENARIO").ok();
    let barrier = std::env::var("RUNNE_TEST_LOCAL_WORKER_BARRIER").ok();
    match (scenario.as_deref(), barrier.as_deref()) {
        (Some("crash-before-go"), Some("pre-release")) => Some("pre-release"),
        (Some("crash-after-create-effect"), Some("after-exit")) => Some("after-exit"),
        (Some("crash-after-create-effect"), Some("after-result-before-step-outcome")) => {
            Some("after-result-before-step-outcome")
        }
        (Some("crash-after-create-effect"), Some("after-terminal")) => Some("after-terminal"),
        _ => None,
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Fixture keeps the exact task, managed effect, authority, barrier, and reopen handles together."
)]
pub(in crate::t1_positive::d2_pending) async fn exercise_active_downgrade(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    workspace_id: runne_runtime_client::CanonicalId,
    task: runne_runtime_client::CanonicalId,
    created: &std::path::Path,
    create_watch: &std::fs::File,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    executable: &std::path::Path,
    session_bus_socket: &std::path::Path,
) {
    let barrier = active_downgrade_barrier().expect("active typed downgrade fixture");
    wait_entered(barrier).await;
    match barrier {
        "pre-release" => {
            assert!(!created.exists(), "create is held before helper GO");
            assert_eq!(
                super::super::super::diagnostic::count_watch_mask(create_watch, libc::IN_CREATE),
                0
            );
            assert_eq!(super::super::verify::result_count(database, task), 0);
            assert_eq!(
                super::super::verify::release_intent_count(database, task),
                0
            );
        }
        "after-exit" => assert_single_create(created, create_watch),
        "after-result-before-step-outcome" => {
            assert_single_create(created, create_watch);
            super::super::verify::assert_encrypted_results(database, task, 1);
            assert_step_outcome_count(database, task, 0);
        }
        "after-terminal" => {
            assert_single_create(created, create_watch);
            super::super::verify::assert_encrypted_results(database, task, 1);
            assert_step_outcome_count(database, task, 1);
            assert_eq!(provider_round_count(database, task), 1);
        }
        _ => unreachable!("barrier was matched above"),
    }

    let selection = commit_ask_always(client, workspace_id, supervisor).await;
    release(barrier);
    let terminal = super::super::verify::wait_success(client, task, database, runtime_root).await;
    assert_ne!(
        terminal.state(),
        runne_runtime_client::TaskRunState::Succeeded,
        "downgrade fenced stale broad-mode continuation"
    );
    let stream_version = terminal.stream_version();
    assert_step_outcome_count(
        database,
        task,
        if barrier == "after-terminal" { 1 } else { 0 },
    );
    assert_eq!(
        super::super::super::diagnostic::fixture_count(
            runtime_root,
            "fixture-provider-request-count"
        ),
        1,
        "downgrade did not dispatch a continuation"
    );
    assert_eq!(provider_round_count(database, task), 1);
    match barrier {
        "pre-release" => {
            assert!(!created.exists());
            assert_eq!(super::super::verify::result_count(database, task), 0);
            assert_eq!(
                super::super::verify::release_intent_count(database, task),
                0
            );
        }
        "after-exit" => assert_encrypted_audit(database, task),
        "after-result-before-step-outcome" => {
            super::super::verify::assert_encrypted_results(database, task, 1);
        }
        "after-terminal" => {
            super::super::verify::assert_encrypted_results(database, task, 1);
            assert_step_outcome_count(database, task, 1);
        }
        _ => unreachable!("barrier was matched above"),
    }
    assert_eq!(
        super::super::super::diagnostic::count_watch_mask(create_watch, libc::IN_CREATE),
        0
    );

    supervisor
        .stop()
        .expect("stop daemon before typed-mode Store reopen");
    let (mut reopened, reopened_client) =
        super::super::crash::restart_same_root(executable, session_bus_socket, runtime_root).await;
    let status = reopened_client
        .permission_mode_status(workspace_id)
        .await
        .expect("read downgraded mode after Store reopen");
    assert_eq!(status.selected_mode, runne_api::PermissionModeV1::AskAlways);
    assert_eq!(status.authorization_revision, selection.revision);
    assert_eq!(
        reopened_client
            .permission_mode_command_status(workspace_id, selection.command_id)
            .await
            .expect("read downgrade receipt after Store reopen"),
        selection.status
    );
    assert_eq!(
        reopened_client
            .request_permission_mode_change(selection.request)
            .await
            .expect("replay downgrade receipt after Store reopen"),
        selection.status
    );
    let reopened_task = reopened_client
        .get_task_run(task)
        .await
        .expect("read terminal TaskRun after Store reopen");
    assert_eq!(reopened_task.state(), terminal.state());
    assert_eq!(reopened_task.stream_version(), stream_version);
    assert_step_outcome_count(
        database,
        task,
        if barrier == "after-terminal" { 1 } else { 0 },
    );
    assert_eq!(
        super::super::super::diagnostic::fixture_count(
            runtime_root,
            "fixture-provider-request-count"
        ),
        1,
        "reopen did not dispatch a continuation"
    );
    assert_eq!(provider_round_count(database, task), 1);
    match barrier {
        "pre-release" => assert!(!created.exists()),
        "after-exit" => {
            assert_create_preserved(created);
            assert_encrypted_audit(database, task);
        }
        "after-result-before-step-outcome" => {
            assert_create_preserved(created);
            super::super::verify::assert_encrypted_results(database, task, 1);
        }
        "after-terminal" => {
            assert_create_preserved(created);
            super::super::verify::assert_encrypted_results(database, task, 1);
            assert_step_outcome_count(database, task, 1);
        }
        _ => unreachable!("barrier was matched above"),
    }
    assert_eq!(
        super::super::super::diagnostic::count_watch_mask(create_watch, libc::IN_CREATE),
        0
    );
    reopened.stop().expect("stop reopened typed-mode runtime");
    eprintln!("PASS: typed create downgrade at {barrier} remained fenced across Store reopen");
}

async fn commit_ask_always(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    workspace_id: runne_runtime_client::CanonicalId,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
) -> CommittedModeSelection {
    let before = client
        .permission_mode_status(workspace_id)
        .await
        .expect("read Full Access mode before downgrade");
    assert_eq!(
        before.selected_mode,
        runne_api::PermissionModeV1::FullAccess
    );
    let (command_id, request) = super::mode_request(
        workspace_id,
        before.authorization_revision,
        runne_api::PermissionModeV1::AskAlways,
    );
    let pending = client.request_permission_mode_change(request.clone()).await;
    super::require_pending_or_readback(client, workspace_id, command_id, pending).await;
    super::commit_current_pending(client, supervisor, command_id).await;
    let status = client
        .permission_mode_command_status(workspace_id, command_id)
        .await
        .expect("read canonical Ask Always downgrade receipt");
    let runne_api::PermissionModeCommandStatusV2::Committed { receipt } = &status else {
        panic!("native confirmation did not commit typed downgrade");
    };
    assert_eq!(
        receipt.selected_mode,
        runne_api::PermissionModeV1::AskAlways
    );
    assert_eq!(
        receipt.authorization_revision,
        before.authorization_revision + 1
    );
    let revision = receipt.authorization_revision;
    CommittedModeSelection {
        mode: runne_api::PermissionModeV1::AskAlways,
        command_id,
        request,
        status,
        revision,
    }
}
