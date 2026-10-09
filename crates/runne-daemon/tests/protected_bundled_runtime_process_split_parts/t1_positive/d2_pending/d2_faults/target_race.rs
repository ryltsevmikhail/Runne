use super::*;
use std::{
    fs::{File, OpenOptions},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::Path,
    time::Duration,
};

const BARRIER_DIRECTORY: &str = ".runne-test-approved-target-race";
const TARGET_NAME: &str = "fixture-created.txt";

#[derive(Debug, PartialEq, Eq)]
struct PermissionRefs {
    attempt_id: Vec<u8>,
    approval_id: Vec<u8>,
    approval_digest: Vec<u8>,
    policy_revision: i64,
    workspace_id: Vec<u8>,
    selected_mode: i64,
    authorization_revision: i64,
    managed_policy_version: i64,
    managed_policy_digest: Vec<u8>,
    decision_source: i64,
    relevant_policy_digest: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

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

fn assert_failure_counts(
    database: &Path,
    runtime_root: &Path,
    task: runne_runtime_client::CanonicalId,
) {
    database::assert_failure_projection(database, task);
    assert_eq!(database::invocation_count(database, task), 1);
    assert_eq!(database::invocation_state(database, task), "audit_only");
    assert_eq!(database::result_count(database, task), 0);
    assert_eq!(database::release_intent_count(database, task), 1);
    assert_eq!(database::managed_area_launch_count(database, task), 1);
    assert_eq!(database::local_stop_state(database, task), Some(2));
    let task_id = id_bytes(task);
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open read-only no-result race view");
    let (has_result_bytes, has_result_digest, has_encrypted_receipt): (bool, bool, bool) =
        connection
            .query_row(
                "SELECT result_bytes IS NOT NULL,result_digest IS NOT NULL,
                    helper_receipt_bytes IS NOT NULL AND receipt_nonce IS NOT NULL
             FROM taskrun_tool_invocations WHERE taskrun_id=?1",
                [task_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("read exact invocation result projection");
    assert!(!has_result_bytes, "no plaintext tool result was released");
    assert!(has_result_digest, "audit-only result digest is retained");
    assert!(has_encrypted_receipt, "encrypted audit receipt is retained");
    assert_eq!(
        fixture_count(runtime_root, "fixture-provider-request-count"),
        1
    );
}

fn permission_refs(database: &Path, task: runne_runtime_client::CanonicalId) -> PermissionRefs {
    let task_id = id_bytes(task);
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open permission race read-only view");
    connection
        .query_row(
            "SELECT i.attempt_id,i.approval_id,i.approval_digest,i.policy_revision,
                    p.workspace_id,p.selected_mode,p.authorization_revision,
                    p.managed_policy_version,p.managed_policy_digest,p.decision_source,
                    p.relevant_policy_digest
             FROM taskrun_tool_invocations i
             JOIN taskrun_tool_permission_admissions p
               USING(taskrun_id,attempt_id,cycle_id,proposal_index)
             WHERE i.taskrun_id=?1 AND i.tool_name='workspace.file.create_new'",
            [task_id.as_slice()],
            |row| {
                Ok(PermissionRefs {
                    attempt_id: row.get(0)?,
                    approval_id: row.get(1)?,
                    approval_digest: row.get(2)?,
                    policy_revision: row.get(3)?,
                    workspace_id: row.get(4)?,
                    selected_mode: row.get(5)?,
                    authorization_revision: row.get(6)?,
                    managed_policy_version: row.get(7)?,
                    managed_policy_digest: row.get(8)?,
                    decision_source: row.get(9)?,
                    relevant_policy_digest: row.get(10)?,
                })
            },
        )
        .expect("read exact create approval and grant bindings")
}

fn assert_public_projection_excludes(
    snapshot: &runne_runtime_client::TaskRunSnapshot,
    canary: &str,
) {
    assert!(
        !format!("{snapshot:?}").contains(canary),
        "outside canary is absent from the public TaskRun projection"
    );
}

fn assert_canary_unchanged(
    canary_watch: &File,
    held_file: &File,
    path: &Path,
    before: &FileIdentity,
    expected: &[u8],
) {
    assert_eq!(
        file_identity(&std::fs::symlink_metadata(path).expect("canary metadata")),
        *before
    );
    assert_eq!(drain_canary_events(canary_watch), (0, 0, 0));
    let mut observed = vec![0_u8; expected.len()];
    let count = held_file
        .read_at(&mut observed, 0)
        .expect("read held canary inode");
    assert!(
        count == expected.len(),
        "outside canary length stayed unchanged"
    );
    assert!(
        observed == expected,
        "outside canary bytes stayed unchanged"
    );
    assert_eq!(
        drain_canary_events(canary_watch),
        (0, 1, 0),
        "only the fixture's held-fd verification read accessed the canary"
    );
}

fn file_identity(metadata: &std::fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

async fn wait_entered(directory: &Path) {
    let entered = directory.join("create.entered");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    loop {
        if let Ok(metadata) = std::fs::symlink_metadata(&entered) {
            assert!(metadata.file_type().is_file());
            assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
            assert_eq!(metadata.mode() & 0o022, 0);
            if std::fs::read(&entered).is_ok_and(|bytes| bytes == b"entered\n") {
                return;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "helper barrier was not entered"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn create_release(directory: &Path) {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o600);
    options
        .open(directory.join("create.release"))
        .expect("create exclusive race release marker");
}

fn named_create_events(watch: &File, name: &str) -> usize {
    let mut events = [0_u8; 4096];
    let mut count = 0;
    loop {
        let read =
            unsafe { libc::read(watch.as_raw_fd(), events.as_mut_ptr().cast(), events.len()) };
        if read < 0 {
            assert_eq!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock
            );
            return count;
        }
        if read == 0 {
            return count;
        }
        let mut offset = 0;
        while offset < read as usize {
            let mask = u32::from_ne_bytes(events[offset + 4..offset + 8].try_into().unwrap());
            let name_len =
                u32::from_ne_bytes(events[offset + 12..offset + 16].try_into().unwrap()) as usize;
            let start = offset + std::mem::size_of::<libc::inotify_event>();
            let event_name = events[start..start + name_len]
                .iter()
                .copied()
                .take_while(|byte| *byte != 0)
                .collect::<Vec<_>>();
            count += usize::from(mask & libc::IN_CREATE != 0 && event_name == name.as_bytes());
            offset = start + name_len;
        }
    }
}

fn open_canary_watch(path: &Path) -> File {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("canary watch path");
    let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
    assert!(fd >= 0, "create canary filesystem observer");
    let watch = unsafe {
        libc::inotify_add_watch(
            fd,
            path.as_ptr(),
            libc::IN_OPEN | libc::IN_ACCESS | libc::IN_MODIFY,
        )
    };
    assert!(watch >= 0, "watch outside canary events");
    unsafe { File::from_raw_fd(fd) }
}

fn drain_canary_events(watch: &File) -> (usize, usize, usize) {
    let mut events = [0_u8; 4096];
    let (mut opened, mut accessed, mut modified) = (0, 0, 0);
    loop {
        let read =
            unsafe { libc::read(watch.as_raw_fd(), events.as_mut_ptr().cast(), events.len()) };
        if read < 0 {
            assert_eq!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock
            );
            return (opened, accessed, modified);
        }
        if read == 0 {
            return (opened, accessed, modified);
        }
        let mut offset = 0;
        while offset < read as usize {
            let mask = u32::from_ne_bytes(events[offset + 4..offset + 8].try_into().unwrap());
            opened += usize::from(mask & libc::IN_OPEN != 0);
            accessed += usize::from(mask & libc::IN_ACCESS != 0);
            modified += usize::from(mask & libc::IN_MODIFY != 0);
            let name_len =
                u32::from_ne_bytes(events[offset + 12..offset + 16].try_into().unwrap()) as usize;
            offset += std::mem::size_of::<libc::inotify_event>() + name_len;
        }
    }
}

fn id_bytes(id: runne_runtime_client::CanonicalId) -> Vec<u8> {
    uuid::Uuid::parse_str(&id.to_string())
        .expect("canonical race fixture id")
        .as_bytes()
        .to_vec()
}

fn mode_number(mode: runne_api::PermissionModeV1) -> i64 {
    match mode {
        runne_api::PermissionModeV1::AskAlways => 1,
        runne_api::PermissionModeV1::RiskBased => 2,
        runne_api::PermissionModeV1::FullAccess => 3,
    }
}
