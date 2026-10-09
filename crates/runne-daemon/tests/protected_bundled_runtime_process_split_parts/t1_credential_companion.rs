use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use sha2::{Digest as _, Sha256};

use super::{material_representations, secret_scan};

const FIXTURE_CREDENTIAL: &[u8] = b"fixture-credential";

pub(crate) fn enabled() -> bool {
    std::env::var_os("RUNNE_TEST_T1_CREDENTIAL_COMPANION").as_deref()
        == Some(std::ffi::OsStr::new("1"))
}

fn scanner() -> secret_scan::SecretScanner {
    secret_scan::SecretScanner::new(material_representations(&[FIXTURE_CREDENTIAL.to_vec()]))
        .unwrap_or_else(|_| panic!("fixture credential scanner"))
}

pub(crate) fn assert_daemon_output(label: &str, stdout: &[u8], stderr: &[u8]) {
    let scanner = scanner();
    let stdout_label = format!("{label} daemon stdout");
    let stderr_label = format!("{label} daemon stderr");
    secret_scan::assert_reader_absent(&scanner, &stdout_label, std::io::Cursor::new(stdout));
    secret_scan::assert_reader_absent(&scanner, &stderr_label, std::io::Cursor::new(stderr));
}

pub(crate) fn assert_runtime_tree(root: &Path) {
    let scanner = scanner();
    let source_binary = std::fs::read(env!("CARGO_BIN_EXE_runned"))
        .expect("read test-support daemon binary source");
    let source_size = u64::try_from(source_binary.len()).expect("daemon binary size fits u64");
    let source_sha256 = hex::encode(Sha256::digest(&source_binary));
    let pinned_binary = root
        .join(".desktop-protected-activation")
        .join("executables-v1")
        .join(format!("{source_sha256}-{source_size}.runned"));
    let mut pinned_binary_seen = false;
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        secret_scan::assert_reader_absent(
            &scanner,
            "daemon runtime path",
            std::io::Cursor::new(path.as_os_str().as_bytes()),
        );
        let metadata = std::fs::symlink_metadata(&path).expect("read daemon runtime entry");
        if path == pinned_binary {
            assert!(
                metadata.file_type().is_file(),
                "pinned daemon cache entry must be a regular file, not a symlink"
            );
            assert_eq!(
                metadata.len(),
                source_size,
                "pinned daemon cache entry size matches the known source binary"
            );
            let cached_binary = std::fs::read(&path).expect("read pinned daemon cache entry");
            assert_eq!(
                hex::encode(Sha256::digest(&cached_binary)),
                source_sha256,
                "pinned daemon cache entry digest matches the known source binary"
            );
            pinned_binary_seen = true;
            continue;
        }
        if metadata.file_type().is_dir() {
            pending.extend(
                std::fs::read_dir(&path)
                    .expect("read daemon runtime directory")
                    .map(|entry| entry.expect("read daemon runtime entry").path()),
            );
        } else if metadata.file_type().is_file() {
            secret_scan::assert_file_absent(&scanner, "daemon runtime file", &path);
        } else if metadata.file_type().is_symlink() {
            let target = std::fs::read_link(&path).expect("read daemon runtime symlink");
            secret_scan::assert_reader_absent(
                &scanner,
                "daemon runtime symlink target",
                std::io::Cursor::new(target.as_os_str().as_bytes()),
            );
        }
    }
    assert!(
        pinned_binary_seen,
        "expected pinned test-support daemon cache entry was scanned"
    );
}

pub(crate) fn assert_projection<T: std::fmt::Debug>(label: &str, projection: &T) {
    let bytes = format!("{projection:?}");
    assert!(!bytes.is_empty(), "{label} public projection was empty");
    secret_scan::assert_reader_absent(&scanner(), label, std::io::Cursor::new(bytes.as_bytes()));
}

pub(crate) async fn assert_public_task_and_approvals(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    workspace_id: runne_runtime_client::CanonicalId,
    database: &Path,
    mode: runne_api::PermissionModeV1,
) {
    let task_runs = client
        .list_task_runs()
        .await
        .expect("read public permission-mode TaskRun projections")
        .into_iter()
        .filter(|task| task.workspace_id() == Some(workspace_id))
        .collect::<Vec<_>>();
    assert_eq!(
        task_runs.len(),
        1,
        "one D2 TaskRun belongs to this workspace"
    );
    let task = &task_runs[0];
    assert_eq!(task.state(), runne_runtime_client::TaskRunState::Succeeded);
    assert_projection("public D2 TaskRun projection", task);

    let pending = client
        .list_pending_approvals()
        .await
        .expect("read public permission-mode approval projections");
    for approval in &pending {
        assert_projection("public pending approval projection", approval);
    }
    assert!(
        pending
            .iter()
            .all(|approval| approval.task_run_id() != task.task_run_id()),
        "completed D2 TaskRun has no pending public approvals"
    );

    if mode == runne_api::PermissionModeV1::AskAlways {
        let task_uuid = uuid::Uuid::parse_str(&task.task_run_id().to_string())
            .expect("canonical D2 TaskRun UUID");
        let connection = rusqlite::Connection::open_with_flags(
            database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .expect("open read-only D2 approval binding view");
        let mut statement = connection
            .prepare(
                "SELECT approval_id FROM taskrun_tool_invocations WHERE taskrun_id=?1 AND tool_name='workspace.file.create_new' ORDER BY round_index",
            )
            .expect("prepare D2 create approval binding query");
        let approval_ids = statement
            .query_map([task_uuid.as_bytes().as_slice()], |row| {
                row.get::<_, Vec<u8>>(0)
            })
            .expect("query D2 create approval binding")
            .collect::<Result<Vec<_>, _>>()
            .expect("decode D2 create approval binding");
        drop(statement);
        drop(connection);
        assert_eq!(
            approval_ids.len(),
            1,
            "AskAlways create invocation has one approval binding"
        );
        let expected_resource = format!("workspace:{workspace_id}:fixture-created.txt");
        for approval_bytes in approval_ids {
            let approval_uuid =
                uuid::Uuid::from_slice(&approval_bytes).expect("D2 approval UUID bytes");
            let approval_id = runne_runtime_client::CanonicalId::parse(&approval_uuid.to_string())
                .expect("canonical D2 approval ID");
            let approval = client
                .get_approval(approval_id)
                .await
                .expect("read public D2 approval projection");
            assert_eq!(approval.task_run_id(), task.task_run_id());
            assert_eq!(approval.action(), "workspace.tool.invoke");
            assert_eq!(approval.resource(), expected_resource);
            assert_eq!(
                approval.state(),
                runne_runtime_client::ApprovalStateDto::Approved
            );
            assert_projection("public approved D2 approval projection", &approval);
        }
    }
}
