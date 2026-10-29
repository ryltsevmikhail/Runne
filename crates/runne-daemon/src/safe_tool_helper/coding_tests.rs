use super::*;
use serde_json::json;
use std::fs;
fn fixture() -> (std::path::PathBuf, File) {
    let dir = std::env::temp_dir().join(format!(
        "runne-coding-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&dir).unwrap();
    let file = File::open(&dir).unwrap();
    (dir, file)
}
fn binding() -> BindingV1 {
    BindingV1 {
        taskrun_id: "11".repeat(16),
        attempt_id: "22".repeat(16),
        cycle_id: "33".repeat(16),
        proposal_index: 0,
        taskrun_version: 1,
        assignment_fence: 1,
        invocation_digest: "44".repeat(32),
        environment_digest: "55".repeat(32),
        approval_digest: "66".repeat(32),
        expires_at_unix_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + 120000,
    }
}
fn invoke(
    root: &File,
    name: &str,
    args: serde_json::Value,
    expected: Option<VersionV1>,
) -> Result<ReceiptV1, &'static str> {
    execute(
        root,
        &serde_json::to_vec(&RequestV1::Coding {
            binding: binding(),
            tool_name: name.into(),
            arguments: args,
            root: identity(root).unwrap(),
            expected,
        })
        .unwrap(),
    )
}
#[test]
fn coding_nested_read_replace_checks_hash_and_stale_version() {
    let (dir, root) = fixture();
    fs::create_dir(dir.join("src")).unwrap();
    fs::write(dir.join("src/a"), b"old").unwrap();
    let before = version(&File::open(dir.join("src/a")).unwrap()).unwrap();
    let read = invoke(
        &root,
        "workspace.file.read",
        json!({"path":"src/a"}),
        Some(before.clone()),
    )
    .unwrap();
    assert_eq!(STANDARD.decode(read.bytes_base64).unwrap(), b"old");
    let args = json!({"path":"src/a","expected_sha256":hex::encode(Sha256::digest(b"old")),"content_base64":STANDARD.encode(b"new")});
    let changed = invoke(
        &root,
        "workspace.file.replace",
        args.clone(),
        Some(before.clone()),
    )
    .unwrap();
    assert_eq!(changed.version, 2);
    assert_eq!(fs::read(dir.join("src/a")).unwrap(), b"new");
    assert!(invoke(&root, "workspace.file.replace", args, Some(before)).is_err());
    assert_eq!(fs::read(dir.join("src/a")).unwrap(), b"new");
    fs::remove_dir_all(dir).unwrap();
}
#[test]
fn coding_rejects_symlink_escape_and_lists_searches_bounded_files() {
    let (dir, root) = fixture();
    fs::create_dir(dir.join("src")).unwrap();
    fs::write(dir.join("src/a"), b"needle here").unwrap();
    std::os::unix::fs::symlink("/tmp", dir.join("escape")).unwrap();
    assert!(
        invoke(
            &root,
            "workspace.file.read",
            json!({"path":"escape/a"}),
            None
        )
        .is_err()
    );
    let target = version(&root).unwrap();
    for (name, args) in [
        ("workspace.files.list", json!({"path":".","limit":20})),
        (
            "workspace.files.search",
            json!({"path":".","query":"needle","limit":20}),
        ),
    ] {
        let receipt = invoke(&root, name, args, Some(target.clone())).unwrap();
        assert!(receipt.byte_length <= 8192);
        assert!(
            String::from_utf8(STANDARD.decode(receipt.bytes_base64).unwrap())
                .unwrap()
                .contains("src/a")
        );
    }
    fs::remove_dir_all(dir).unwrap();
}
#[test]
fn coding_command_preserves_exit_and_bounded_output() {
    let (dir, root) = fixture();
    let receipt = invoke(
        &root,
        "workspace.command.run",
        json!({"cwd":".","argv":["/usr/bin/printf","hello"],"timeout_ms":1000}),
        Some(version(&root).unwrap()),
    )
    .unwrap();
    let output: serde_json::Value =
        serde_json::from_slice(&STANDARD.decode(receipt.bytes_base64).unwrap()).unwrap();
    assert_eq!(output["exit_code"], 0);
    assert_eq!(output["stdout_base64"], STANDARD.encode("hello"));
    fs::remove_dir_all(dir).unwrap();
}
#[test]
fn coding_create_is_absent_only_and_binds_created_content() {
    let (dir, root) = fixture();
    fs::create_dir(dir.join("src")).unwrap();
    let args = json!({"path":"src/new","content_base64":STANDARD.encode(b"created")});
    let receipt = invoke(&root, "workspace.file.create_new", args.clone(), None).unwrap();
    assert_eq!(STANDARD.decode(receipt.bytes_base64).unwrap(), b"created");
    assert_eq!(fs::read(dir.join("src/new")).unwrap(), b"created");
    assert!(invoke(&root, "workspace.file.create_new", args, None).is_err());
    fs::remove_dir_all(dir).unwrap();
}
#[test]
fn coding_command_times_out_and_bounds_flooded_output() {
    let (dir, root) = fixture();
    let receipt=invoke(&root,"workspace.command.run",json!({"cwd":".","argv":["/usr/bin/sh","-c","while :; do printf 0123456789; done"],"timeout_ms":40}),Some(version(&root).unwrap())).unwrap();
    let output: serde_json::Value =
        serde_json::from_slice(&STANDARD.decode(receipt.bytes_base64).unwrap()).unwrap();
    assert_eq!(output["timed_out"], true);
    assert_eq!(output["output_truncated"], true);
    assert!(
        STANDARD
            .decode(output["stdout_base64"].as_str().unwrap())
            .unwrap()
            .len()
            <= 2048
    );
    fs::remove_dir_all(dir).unwrap();
}
