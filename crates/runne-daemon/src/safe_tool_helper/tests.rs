use super::*;
use std::fs;
use std::os::fd::FromRawFd;
use std::time::{SystemTime, UNIX_EPOCH};

fn fixture() -> (std::path::PathBuf, File) {
    let path = std::env::temp_dir().join(format!(
        "runne-safe-tool-helper-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&path).unwrap();
    let root = File::open(&path).unwrap();
    (path, root)
}

fn binding() -> BindingV1 {
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        + 60_000;
    BindingV1 {
        taskrun_id: "018f2e3a-7000-7000-8000-000000000010".into(),
        attempt_id: "018f2e3a-7000-7000-8000-000000000011".into(),
        cycle_id: "018f2e3a-7000-7000-8000-000000000012".into(),
        proposal_index: 0,
        taskrun_version: 4,
        assignment_fence: 2,
        invocation_digest: "11".repeat(32),
        environment_digest: "22".repeat(32),
        approval_digest: "33".repeat(32),
        expires_at_unix_ms: expiry,
    }
}

#[test]
fn reads_exact_regular_file_and_returns_actual_bytes_digest_and_binding() {
    let (directory, root) = fixture();
    fs::write(directory.join("notes.txt"), b"read result").unwrap();
    let file = File::open(directory.join("notes.txt")).unwrap();
    let request = RequestV1::Read {
        binding: binding(),
        path: "notes.txt".into(),
        root: identity(&root).unwrap(),
        expected: version(&file).unwrap(),
    };
    let encoded = serde_json::to_vec(&request).unwrap();
    let receipt = execute(&root, &encoded).unwrap();

    assert_eq!(receipt.status, "success");
    assert_eq!(receipt.bytes_base64, STANDARD.encode(b"read result"));
    assert_eq!(receipt.byte_length, 11);
    assert_eq!(receipt.sha256, hex::encode(Sha256::digest(b"read result")));
    assert!(receipt.binding.expires_at_unix_ms > 0);
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn create_new_is_absent_only_durable_and_duplicate_denied() {
    let (directory, root) = fixture();
    let binding = binding();
    let root_identity = identity(&root).unwrap();
    let request = serde_json::json!({
        "operation": "CreateNew",
        "binding": binding,
        "path": "created.txt",
        "root": root_identity,
        "expected_absent": true,
        "content_base64": STANDARD.encode(b"created safely"),
    });
    let encoded = serde_json::to_vec(&request).unwrap();
    let receipt = execute(&root, &encoded).unwrap();

    assert_eq!(receipt.operation, "create_new");
    assert_eq!(receipt.bytes_base64, STANDARD.encode(b"created safely"));
    assert_eq!(
        fs::read(directory.join("created.txt")).unwrap(),
        b"created safely"
    );
    assert!(matches!(
        execute(&root, &encoded),
        Err("target_exists_or_denied")
    ));
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn read_target_drift_and_nonflat_paths_are_denied() {
    let (directory, root) = fixture();
    fs::write(directory.join("target.txt"), b"original").unwrap();
    let file = File::open(directory.join("target.txt")).unwrap();
    let stale = version(&file).unwrap();
    fs::write(directory.join("target.txt"), b"changed! ").unwrap();
    let request = serde_json::json!({
        "operation": "Read",
        "binding": binding(),
        "path": "target.txt",
        "root": identity(&root).unwrap(),
        "expected": stale,
    });
    assert!(matches!(
        execute(&root, &serde_json::to_vec(&request).unwrap()),
        Err("target_changed")
    ));
    assert_eq!(valid_path("../target.txt".into()), Err("path_denied"));
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn read_rejects_fifo_metadata_without_opening_it_for_io() {
    let (directory, root) = fixture();
    let name = CString::new("blocked.fifo").unwrap();
    assert_eq!(
        unsafe { libc::mkfifoat(root.as_raw_fd(), name.as_ptr(), 0o600) },
        0
    );
    let watcher_fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
    assert!(watcher_fd >= 0);
    let watcher = unsafe { File::from_raw_fd(watcher_fd) };
    let directory_c = CString::new(directory.as_os_str().as_encoded_bytes()).unwrap();
    assert!(
        unsafe {
            libc::inotify_add_watch(watcher.as_raw_fd(), directory_c.as_ptr(), libc::IN_OPEN)
        } >= 0
    );
    let path = valid_path("blocked.fifo".into()).unwrap();
    let pinned = openat(&root, &path, libc::O_PATH | libc::O_NOFOLLOW).unwrap();
    let request = RequestV1::Read {
        binding: binding(),
        path: "blocked.fifo".into(),
        root: identity(&root).unwrap(),
        expected: version(&pinned).unwrap(),
    };
    assert!(matches!(
        execute(&root, &serde_json::to_vec(&request).unwrap()),
        Err("target_changed")
    ));
    let mut events = [0_u8; 1024];
    let read = unsafe {
        libc::read(
            watcher.as_raw_fd(),
            events.as_mut_ptr().cast(),
            events.len(),
        )
    };
    assert_eq!(read, -1, "target validation must not open the FIFO for I/O");
    assert_eq!(
        std::io::Error::last_os_error().kind(),
        std::io::ErrorKind::WouldBlock
    );
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn create_receipt_cannot_substitute_content_approved_by_arguments() {
    use runne_domain::id::{AttemptId, CycleId, IntegrityDigest, TaskRunId};
    use runne_store::store::taskrun_tool_invocation::{ToolInvocationBindingV1, ToolInvocationKey};
    let args = br#"{"content_base64":"YXBwcm92ZWQ=","path":"new.txt"}"#.to_vec();
    let digest = |byte| IntegrityDigest::from_bytes([byte; 32]);
    let binding = ToolInvocationBindingV1 {
        key: ToolInvocationKey {
            taskrun_id: TaskRunId::from_bytes([1; 16]),
            attempt_id: AttemptId::from_bytes([2; 16]),
            cycle_id: CycleId::from_bytes([3; 16]),
            proposal_index: 0,
        },
        expected_taskrun_version: 4,
        call_id: "call".into(),
        tool_name: "workspace.file.create_new".into(),
        tool_revision: "1".into(),
        schema_digest: digest(4),
        arguments_digest: IntegrityDigest::from_bytes(Sha256::digest(&args).into()),
        canonical_arguments: args,
        semantic_digest: digest(6),
        sources: Vec::new(),
        environment_id: "linux-agent-tools-v1".into(),
        environment_revision: "1".into(),
        root_identity: digest(7),
        root_revision: 1,
        target_name: "new.txt".into(),
        target_precondition: None,
        approval_id: [8; 16],
        principal_id: "owner".into(),
        approval_principal_id: "owner".into(),
        approval_action: "workspace.tool.invoke".into(),
        approval_resource: "workspace:file".into(),
        approval_digest: digest(9),
        policy_revision: 1,
        approval_expires_at: 2_000_000_000_000,
        round_index: 0,
    };
    let receipt = ReceiptV1 {
        status: "success".into(),
        version: 1,
        operation: "create_new".into(),
        path: "new.txt".into(),
        binding: protocol::BindingV1 {
            taskrun_id: binding.key.taskrun_id.to_string(),
            attempt_id: binding.key.attempt_id.to_string(),
            cycle_id: binding.key.cycle_id.to_string(),
            proposal_index: 0,
            taskrun_version: 4,
            assignment_fence: 2,
            invocation_digest: hex::encode(binding.semantic_digest.as_bytes()),
            environment_digest: hex::encode(Sha256::digest(b"linux-agent-tools-v1\x01")),
            approval_digest: hex::encode(binding.approval_digest.as_bytes()),
            expires_at_unix_ms: binding.approval_expires_at as u64,
        },
        root: IdentityV1 {
            device: 1,
            inode: 2,
        },
        target: VersionV1 {
            device: 1,
            inode: 3,
            size: 5,
            mtime_sec: 1,
            mtime_nsec: 0,
            ctime_sec: 1,
            ctime_nsec: 0,
        },
        bytes_base64: STANDARD.encode(b"wrong"),
        byte_length: 5,
        truncated: false,
        sha256: hex::encode(Sha256::digest(b"wrong")),
    };
    assert!(
        verify_bound_receipt(
            &binding,
            &binding.canonical_arguments,
            2,
            &serde_json::to_vec(&receipt).unwrap(),
            digest(10),
            5,
        )
        .is_err()
    );
}
