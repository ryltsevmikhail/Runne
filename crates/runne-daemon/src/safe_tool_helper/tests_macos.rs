use super::*;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

fn fixture() -> (std::path::PathBuf, File) {
    let path = std::env::temp_dir().join(format!(
        "runne-safe-tool-helper-macos-{}-{}-{}",
        std::process::id(),
        NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed),
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

fn coding(
    root: &File,
    tool: &str,
    arguments: serde_json::Value,
    expected: Option<VersionV1>,
) -> Result<ReceiptV1, &'static str> {
    let request = RequestV1::Coding {
        binding: binding(),
        tool_name: tool.into(),
        arguments,
        root: identity(root).unwrap(),
        expected,
    };
    execute(root, &serde_json::to_vec(&request).unwrap())
}

#[test]
fn reads_regular_file_through_a_walked_component_path() {
    let (directory, root) = fixture();
    fs::create_dir(directory.join("nested")).unwrap();
    fs::write(directory.join("nested/notes.txt"), b"macos read").unwrap();
    let expected = version(&File::open(directory.join("nested/notes.txt")).unwrap()).unwrap();
    let receipt = coding(
        &root,
        "workspace.file.read",
        serde_json::json!({"path": "nested/notes.txt"}),
        Some(expected),
    )
    .unwrap();
    assert_eq!(receipt.bytes_base64, STANDARD.encode(b"macos read"));
    assert_eq!(receipt.sha256, hex::encode(Sha256::digest(b"macos read")));
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn create_new_is_absent_only_and_duplicate_is_denied() {
    let (directory, root) = fixture();
    let encoded = serde_json::to_vec(&RequestV1::Coding {
        binding: binding(),
        tool_name: "workspace.file.create_new".into(),
        arguments: serde_json::json!({
            "path": "created.txt",
            "content_base64": STANDARD.encode(b"created on macOS"),
        }),
        root: identity(&root).unwrap(),
        expected: None,
    })
    .unwrap();
    let receipt = execute(&root, &encoded).unwrap();
    assert_eq!(receipt.operation, "create_new");
    assert_eq!(
        fs::read(directory.join("created.txt")).unwrap(),
        b"created on macOS"
    );
    assert!(matches!(execute(&root, &encoded), Err("target_exists")));
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn replace_requires_the_exact_content_digest() {
    let (directory, root) = fixture();
    fs::write(directory.join("target.txt"), b"old").unwrap();
    let old_digest = hex::encode(Sha256::digest(b"old"));
    let arguments = serde_json::json!({
        "path": "target.txt",
        "content_base64": STANDARD.encode(b"new content"),
        "expected_sha256": old_digest,
    });
    let before = version(&File::open(directory.join("target.txt")).unwrap()).unwrap();
    let receipt = coding(&root, "workspace.file.replace", arguments, Some(before)).unwrap();
    assert_eq!(receipt.operation, "replace");
    assert_eq!(
        fs::read(directory.join("target.txt")).unwrap(),
        b"new content"
    );
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn list_and_search_walk_the_pinned_directory() {
    let (directory, root) = fixture();
    fs::create_dir(directory.join("src")).unwrap();
    fs::write(directory.join("src/main.txt"), b"needle here").unwrap();
    let root_version = version(&File::open(&directory).unwrap()).unwrap();
    let listed = coding(
        &root,
        "workspace.files.list",
        serde_json::json!({"path": ".", "limit": 10}),
        Some(root_version.clone()),
    )
    .unwrap();
    let listed: serde_json::Value =
        serde_json::from_slice(&STANDARD.decode(listed.bytes_base64).unwrap()).unwrap();
    assert_eq!(listed["entries"][0]["path"], "src/main.txt");

    let searched = coding(
        &root,
        "workspace.files.search",
        serde_json::json!({"path": ".", "query": "needle", "limit": 10}),
        Some(root_version),
    )
    .unwrap();
    let searched: serde_json::Value =
        serde_json::from_slice(&STANDARD.decode(searched.bytes_base64).unwrap()).unwrap();
    assert_eq!(searched["entries"][0]["path"], "src/main.txt");
    fs::remove_dir_all(directory).unwrap();
}

/// Returns `true` when the environment cannot exercise the sandbox at all.
fn unsupported_environment(error: &str) -> bool {
    match error {
        "command_spawn_policy" => {
            eprintln!("skipping: Seatbelt cannot be applied in this process tree");
            true
        }
        "command_helper_missing" | "command_helper_untrusted" => {
            eprintln!("skipping: no Developer ID signed runne-sandbox-helper for this test");
            true
        }
        _ => false,
    }
}

fn command(
    root: &File,
    directory: &std::path::Path,
    arguments: serde_json::Value,
) -> Option<serde_json::Value> {
    let expected = version(&File::open(directory).unwrap()).unwrap();
    match coding(root, "workspace.command.run", arguments, Some(expected)) {
        Ok(receipt) => {
            Some(serde_json::from_slice(&STANDARD.decode(receipt.bytes_base64).unwrap()).unwrap())
        }
        Err(error) if unsupported_environment(error) => None,
        Err(error) => panic!("command failed: {error}"),
    }
}

#[test]
fn command_runs_inside_the_signed_seatbelt_helper() {
    let (directory, root) = fixture();
    let Some(output) = command(
        &root,
        &directory,
        serde_json::json!({
            "cwd": ".",
            "argv": ["/bin/pwd"],
            "timeout_ms": 5000,
        }),
    ) else {
        fs::remove_dir_all(directory).unwrap();
        return;
    };
    assert_eq!(output["exit_code"], 0);
    let stdout = STANDARD
        .decode(output["stdout_base64"].as_str().unwrap())
        .unwrap();
    let printed = std::str::from_utf8(&stdout).unwrap().trim_end();
    assert_eq!(
        std::fs::canonicalize(printed).unwrap(),
        std::fs::canonicalize(&directory).unwrap()
    );
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn command_confines_reads_and_writes_to_the_workspace() {
    let (directory, root) = fixture();
    let Some(read_denied) = command(
        &root,
        &directory,
        serde_json::json!({
            "cwd": ".",
            "argv": ["/bin/cat", "/etc/passwd"],
            "timeout_ms": 5000,
        }),
    ) else {
        fs::remove_dir_all(directory).unwrap();
        return;
    };
    assert_ne!(read_denied["exit_code"], 0);
    assert_eq!(read_denied["stdout_base64"], "");

    let outside = std::env::temp_dir().join(format!("runne-outside-{}", std::process::id()));
    let _ = fs::remove_file(&outside);
    let Some(write_denied) = command(
        &root,
        &directory,
        serde_json::json!({
            "cwd": ".",
            "argv": ["/usr/bin/touch", outside.to_str().unwrap()],
            "timeout_ms": 5000,
        }),
    ) else {
        fs::remove_dir_all(directory).unwrap();
        return;
    };
    assert_ne!(write_denied["exit_code"], 0);
    assert!(!outside.exists());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn symlinked_ancestor_and_leaf_are_rejected() {
    let (directory, root) = fixture();
    let outside = fixture();
    fs::write(outside.0.join("secret.txt"), b"outside").unwrap();
    std::os::unix::fs::symlink(&outside.0, directory.join("escape")).unwrap();
    std::os::unix::fs::symlink(outside.0.join("secret.txt"), directory.join("leaf")).unwrap();

    for path in ["escape/secret.txt", "leaf"] {
        assert_eq!(
            coding(
                &root,
                "workspace.file.read",
                serde_json::json!({"path": path}),
                None,
            ),
            Err("target_denied")
        );
    }
    fs::remove_dir_all(directory).unwrap();
    fs::remove_dir_all(outside.0).unwrap();
}

#[test]
fn primitive_open_beneath_rejects_parent_component() {
    let (directory, root) = fixture();
    let error = super::platform::open_beneath(
        &root,
        &std::ffi::CString::new("../outside").unwrap(),
        libc::O_RDONLY,
        0,
    )
    .unwrap_err();
    assert_eq!(error, "target_denied");
    fs::remove_dir_all(directory).unwrap();
}
