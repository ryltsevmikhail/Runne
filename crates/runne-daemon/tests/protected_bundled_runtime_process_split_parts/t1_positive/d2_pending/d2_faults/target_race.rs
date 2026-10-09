use super::*;
use std::{
    fs::File,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
    time::Duration,
};

#[path = "target_race/canary_watch.rs"]
mod canary_watch;
#[path = "target_race/facts.rs"]
mod facts;
use canary_watch::*;
use facts::*;

#[expect(
    clippy::too_many_arguments,
    reason = "The race fixture retains the exact client, task, workspace, and same-root restart handles."
)]
pub(super) async fn exercise(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    task: runne_runtime_client::CanonicalId,
    workspace_id: runne_runtime_client::CanonicalId,
    project_directory: &Path,
    database: &Path,
    runtime_root: &Path,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    executable: &Path,
    session_bus_socket: &Path,
    create_watch: &File,
) {
    assert_eq!(
        std::env::var("RUNNE_TEST_T1_APPROVED_TARGET_RACE").as_deref(),
        Ok("1")
    );
    assert_eq!(
        std::env::var("RUNNE_TEST_D2_TOOL_SCENARIO").as_deref(),
        Ok("approved-target-create-race")
    );
    let permission_mode = std::env::var("RUNNE_TEST_D2_PERMISSION_MODE")
        .expect("race runs with an explicit managed-Ask mode");
    let expected_mode = match permission_mode.as_str() {
        "ask_always" => runne_api::PermissionModeV1::AskAlways,
        "risk_based" => runne_api::PermissionModeV1::RiskBased,
        "full_access" => runne_api::PermissionModeV1::FullAccess,
        _ => panic!("unsupported permission mode fixture"),
    };
    let selected_before = client
        .permission_mode_status(workspace_id)
        .await
        .expect("read selected permission mode before target race");
    assert_eq!(selected_before.selected_mode, expected_mode);
    assert!(selected_before.authorization_revision > 0);

    let barrier_directory = project_directory.join(BARRIER_DIRECTORY);
    assert!(!barrier_directory.exists());
    std::fs::create_dir(&barrier_directory).expect("create reserved workspace race barrier");
    std::fs::set_permissions(&barrier_directory, std::fs::Permissions::from_mode(0o700))
        .expect("restrict workspace race barrier");
    let target = project_directory.join(TARGET_NAME);
    let retained = project_directory.join("fixture-created.retained");
    let outside = project_directory
        .parent()
        .expect("project parent directory")
        .join("outside-secret.txt");
    let canary = format!("D21_APPROVED_TARGET_RACE_CANARY_{}", uuid::Uuid::new_v4());
    let canary_bytes = canary.as_bytes();
    std::fs::write(&outside, canary_bytes).expect("seed outside canary");
    let outside_file = File::open(&outside).expect("hold outside canary inode");
    let outside_before =
        file_identity(&std::fs::symlink_metadata(&outside).expect("canary metadata"));
    let canary_watch = open_canary_watch(&outside);

    let approval = super::flows::wait_approval(client, task, database, runtime_root).await;
    assert_eq!(approval.action(), "workspace.tool.invoke");
    assert!(approval.resource().contains(TARGET_NAME));
    assert!(
        approval
            .risk_summary()
            .contains("workspace.file.create_new")
    );
    assert!(!target.exists(), "pending FsCreate has no target effect");
    assert_eq!(named_create_events(create_watch, TARGET_NAME), 0);
    assert_eq!(database::invocation_count(database, task), 1);
    assert_eq!(database::release_intent_count(database, task), 0);
    assert_eq!(database::managed_area_launch_count(database, task), 0);
    assert_eq!(database::result_count(database, task), 0);
    assert_eq!(
        fixture_count(runtime_root, "fixture-provider-request-count"),
        1
    );
    crate::t1_positive::managed_ask::assert_pending_create_no_release(database, task, &approval);
    let refs_before = permission_refs(database, task);
    assert_eq!(refs_before.approval_id, id_bytes(approval.approval_id()));
    assert_eq!(refs_before.workspace_id, id_bytes(workspace_id));
    assert_eq!(refs_before.selected_mode, mode_number(expected_mode));
    assert_eq!(
        refs_before.authorization_revision as u64,
        selected_before.authorization_revision
    );

    let ack = super::flows::decide(
        client,
        &approval,
        runne_runtime_client::ApprovalDecisionDto::Approve,
        "approved-target-race",
    )
    .await
    .expect("approve exact FsCreate request");
    assert_eq!(
        ack.state(),
        runne_runtime_client::ApprovalStateDto::Approved
    );
    let approved = client
        .get_approval(approval.approval_id())
        .await
        .expect("read approved FsCreate request");
    assert_eq!(approved.action_digest(), approval.action_digest());
    assert_eq!(approved.policy_revision(), approval.policy_revision());
    assert_eq!(
        approved.state(),
        runne_runtime_client::ApprovalStateDto::Approved
    );
    assert_eq!(permission_refs(database, task), refs_before);

    wait_entered(&barrier_directory).await;
    let mut target_creates = named_create_events(create_watch, TARGET_NAME);
    assert_eq!(
        target_creates, 1,
        "helper O_EXCL created the approved target"
    );
    assert_eq!(
        named_create_events(create_watch, TARGET_NAME),
        0,
        "no second create occurred before replacement"
    );
    let empty_original = std::fs::symlink_metadata(&target).expect("O_EXCL original metadata");
    assert!(empty_original.file_type().is_file());
    assert_eq!(empty_original.len(), 0);
    assert_eq!(empty_original.nlink(), 1);
    let original_identity = file_identity(&empty_original);
    std::fs::rename(&target, &retained).expect("retain the helper-created inode");
    let moved_metadata = std::fs::symlink_metadata(&retained).expect("retained inode metadata");
    let moved_identity = file_identity(&moved_metadata);
    assert_eq!(moved_identity.device, original_identity.device);
    assert_eq!(moved_identity.inode, original_identity.inode);
    assert_eq!(moved_identity.length, 0);
    assert_eq!(moved_metadata.nlink(), 1);
    std::os::unix::fs::symlink(&outside, &target)
        .expect("replace approved path with canary symlink");
    assert!(
        std::fs::symlink_metadata(&target)
            .expect("replacement metadata")
            .file_type()
            .is_symlink()
    );
    target_creates += named_create_events(create_watch, TARGET_NAME);
    assert_eq!(
        target_creates, 2,
        "one O_EXCL create and one parent symlink create"
    );
    create_release(&barrier_directory);

    let state = super::flows::wait_terminal(client, task, database, runtime_root).await;
    assert_eq!(state, runne_runtime_client::TaskRunState::Failed);
    let before_restart = client
        .get_task_run(task)
        .await
        .expect("read failed race TaskRun");
    assert_public_projection_excludes(&before_restart, &canary);
    assert_eq!(
        before_restart.state(),
        runne_runtime_client::TaskRunState::Failed
    );
    assert_failure_counts(database, runtime_root, task);
    assert_eq!(permission_refs(database, task), refs_before);
    assert_eq!(
        named_create_events(create_watch, TARGET_NAME),
        0,
        "helper did not recreate the replaced name"
    );
    let written_identity =
        file_identity(&std::fs::symlink_metadata(&retained).expect("retained inode after write"));
    assert_eq!(written_identity.device, original_identity.device);
    assert_eq!(written_identity.inode, original_identity.inode);
    assert_eq!(
        written_identity.length,
        super::super::positive::CREATE_BYTES.len() as u64
    );
    assert!(
        std::fs::read(&retained)
            .is_ok_and(|contents| contents == super::super::positive::CREATE_BYTES),
        "approved bytes were written to the original inode"
    );
    assert_canary_unchanged(
        &canary_watch,
        &outside_file,
        &outside,
        &outside_before,
        canary_bytes,
    );
    assert_eq!(
        fixture_count(runtime_root, "fixture-provider-request-count"),
        1,
        "no provider continuation followed the audit-only helper result"
    );

    supervisor
        .stop()
        .expect("stop exact D2 daemon after terminal failure");
    let (mut reopened, reopened_client) =
        super::super::positive::restart_same_root(executable, session_bus_socket, runtime_root)
            .await;
    let reopened_task = reopened_client
        .get_task_run(task)
        .await
        .expect("read same-root recovered TaskRun");
    assert_eq!(
        reopened_task.state(),
        runne_runtime_client::TaskRunState::Failed
    );
    assert_eq!(
        reopened_task.stream_version(),
        before_restart.stream_version()
    );
    assert_public_projection_excludes(&reopened_task, &canary);
    assert_failure_counts(database, runtime_root, task);
    assert_eq!(permission_refs(database, task), refs_before);
    assert_eq!(
        named_create_events(create_watch, TARGET_NAME),
        0,
        "same-root recovery made no second target effect"
    );
    assert!(
        std::fs::symlink_metadata(&target)
            .expect("replacement path after recovery")
            .file_type()
            .is_symlink()
    );
    let selected_after = reopened_client
        .permission_mode_status(workspace_id)
        .await
        .expect("read mode after Store reopen");
    assert_eq!(selected_after.selected_mode, selected_before.selected_mode);
    assert_eq!(
        selected_after.authorization_revision,
        selected_before.authorization_revision
    );
    crate::t1_positive::managed_ask::assert_retained_sidecar(database);
    assert_canary_unchanged(
        &canary_watch,
        &outside_file,
        &outside,
        &outside_before,
        canary_bytes,
    );
    assert_eq!(
        file_identity(&std::fs::symlink_metadata(&retained).expect("retained inode after reopen")),
        written_identity
    );
    assert!(
        std::fs::read(&retained)
            .is_ok_and(|contents| contents == super::super::positive::CREATE_BYTES),
        "same-root recovery retained the original inode bytes"
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    let stable = reopened_client
        .get_task_run(task)
        .await
        .expect("recheck recovered failed TaskRun");
    assert_eq!(stable.state(), runne_runtime_client::TaskRunState::Failed);
    assert_eq!(stable.stream_version(), before_restart.stream_version());
    assert_failure_counts(database, runtime_root, task);
    assert_eq!(permission_refs(database, task), refs_before);
    assert_eq!(
        fixture_count(runtime_root, "fixture-provider-request-count"),
        1,
        "recovery did not continue the provider conversation"
    );
    assert_eq!(named_create_events(create_watch, TARGET_NAME), 0);
    assert_canary_unchanged(
        &canary_watch,
        &outside_file,
        &outside,
        &outside_before,
        canary_bytes,
    );
    reopened
        .stop()
        .expect("stop same-root race recovery daemon");
}
