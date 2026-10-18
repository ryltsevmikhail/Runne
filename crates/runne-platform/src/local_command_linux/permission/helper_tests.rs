use super::{
    helper::{
        PermissionHelperObservationV1, PermissionHelperOperationV1, validate_helper_byte_budget,
    },
    helper_protocol,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use runne_application::permission_modes::FilesystemPermission;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    time::{SystemTime, UNIX_EPOCH},
};

fn expiry(offset_ms: i64) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    u64::try_from(now + offset_ms).unwrap()
}

fn binding(expires_at_unix_ms: u64) -> Value {
    json!({
        "taskrun_id": "11111111-1111-4111-8111-111111111111",
        "attempt_id": "22222222-2222-4222-8222-222222222222",
        "cycle_id": "33333333-3333-4333-8333-333333333333",
        "proposal_index": 4,
        "taskrun_version": 5,
        "assignment_fence": 6,
        "invocation_digest": "44".repeat(32),
        "environment_digest": "55".repeat(32),
        "approval_digest": "66".repeat(32),
        "expires_at_unix_ms": expires_at_unix_ms,
    })
}

fn root_identity(path: &std::path::Path) -> Value {
    let metadata = fs::metadata(path).unwrap();
    json!({"device": metadata.dev(), "inode": metadata.ino()})
}

fn file_version(path: &std::path::Path) -> Value {
    let metadata = fs::metadata(path).unwrap();
    json!({
        "device": metadata.dev(),
        "inode": metadata.ino(),
        "size": metadata.len(),
        "mtime_sec": metadata.mtime(),
        "mtime_nsec": metadata.mtime_nsec(),
        "ctime_sec": metadata.ctime(),
        "ctime_nsec": metadata.ctime_nsec(),
    })
}

fn read_request(root: Value, path: &str, target: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "operation": "Read",
        "binding": binding(expiry(60_000)),
        "path": path,
        "root": root,
        "expected": target,
    }))
    .unwrap()
}

fn create_request(root: Value, path: &str, content: &[u8]) -> (Vec<u8>, String) {
    let content_base64 = STANDARD.encode(content);
    let bytes = serde_json::to_vec(&json!({
        "operation": "CreateNew",
        "binding": binding(expiry(60_000)),
        "path": path,
        "root": root,
        "expected_absent": true,
        "content_base64": content_base64.clone(),
    }))
    .unwrap();
    (bytes, content_base64)
}

fn arguments_digest(path: &str, content_base64: Option<&str>) -> [u8; 32] {
    let value = match content_base64 {
        Some(value) => json!({"path": path, "content_base64": value}),
        None => json!({"path": path}),
    };
    Sha256::digest(serde_json::to_vec(&value).unwrap()).into()
}

fn observation(bytes: &[u8]) -> PermissionHelperObservationV1 {
    helper_protocol::parse_helper_request(bytes)
        .unwrap()
        .observation
}

#[test]
fn encoded_read_binds_parsed_identity_arguments_and_actual_target_version() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("read-target");
    fs::write(&path, b"pinned read bytes").unwrap();
    let bytes = read_request(
        root_identity(directory.path()),
        "read-target",
        file_version(&path),
    );
    let parsed = helper_protocol::parse_helper_request(&bytes).unwrap();
    let workspace = fs::File::open(directory.path()).unwrap();

    assert_eq!(
        parsed.observation.operation(),
        PermissionHelperOperationV1::Read
    );
    assert_eq!(
        PermissionHelperOperationV1::Read.permissions(),
        &[FilesystemPermission::Read]
    );
    assert_eq!(
        parsed.observation.arguments_digest(),
        &arguments_digest("read-target", None)
    );
    assert_eq!(
        parsed.observation.binding().taskrun_id,
        "11111111-1111-4111-8111-111111111111"
    );
    assert_eq!(parsed.observation.binding().taskrun_version, 5);
    assert_eq!(parsed.observation.binding().proposal_index, 4);
    assert_eq!(parsed.observation.binding().assignment_fence, 6);
    assert_eq!(
        parsed.observation.binding().invocation_digest,
        "44".repeat(32)
    );
    assert_eq!(
        parsed.observation.binding().environment_digest,
        "55".repeat(32)
    );
    assert_eq!(
        parsed.observation.binding().approval_digest,
        "66".repeat(32)
    );
    assert!(parsed.observation.binding().expires_at_unix_ms > expiry(-1));
    assert_eq!(parsed.observation.content_length(), 0);
    assert_eq!(parsed.observation.target_version().unwrap().size, 17);
    helper_protocol::check_helper_target(&parsed, &workspace).unwrap();

    fs::write(&path, b"changed target version").unwrap();
    assert!(helper_protocol::check_helper_target(&parsed, &workspace).is_err());
}

#[test]
fn encoded_create_new_empty_and_nonempty_keep_the_same_three_rights() {
    let directory = tempfile::tempdir().unwrap();
    let root = root_identity(directory.path());
    let workspace = fs::File::open(directory.path()).unwrap();

    for (path, content) in [
        ("empty-target", &[][..]),
        ("content-target", b"created bytes".as_slice()),
    ] {
        let (bytes, spelling) = create_request(root.clone(), path, content);
        let parsed = helper_protocol::parse_helper_request(&bytes).unwrap();
        assert_eq!(
            parsed.observation.operation(),
            PermissionHelperOperationV1::CreateNew
        );
        assert_eq!(
            PermissionHelperOperationV1::CreateNew.permissions(),
            &[
                FilesystemPermission::Read,
                FilesystemPermission::Create,
                FilesystemPermission::Write,
            ]
        );
        assert_eq!(parsed.observation.content_length(), content.len());
        let content_digest: [u8; 32] = Sha256::digest(content).into();
        assert_eq!(parsed.observation.content_digest(), &content_digest);
        assert_eq!(
            parsed.observation.arguments_digest(),
            &arguments_digest(path, Some(&spelling))
        );
        assert_eq!(parsed.observation.target_version(), None);
        helper_protocol::check_helper_target(&parsed, &workspace).unwrap();

        fs::write(directory.path().join(path), content).unwrap();
        assert!(helper_protocol::check_helper_target(&parsed, &workspace).is_err());
    }
}

#[test]
fn helper_request_must_fit_the_declared_byte_budget() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("budget-read");
    fs::write(&path, b"read").unwrap();
    let read = observation(&read_request(
        root_identity(directory.path()),
        "budget-read",
        file_version(&path),
    ));
    assert!(validate_helper_byte_budget(Some(4), &read).is_ok());
    assert!(validate_helper_byte_budget(Some(3), &read).is_err());

    let root = root_identity(directory.path());
    let (empty_request, _) = create_request(root.clone(), "budget-empty", b"");
    let empty = observation(&empty_request);
    assert!(validate_helper_byte_budget(Some(0), &empty).is_ok());

    let (create_request, _) = create_request(root, "budget-create", b"data");
    let create = observation(&create_request);
    assert!(validate_helper_byte_budget(Some(4), &create).is_ok());
    assert!(validate_helper_byte_budget(Some(3), &create).is_err());
}

#[test]
fn exact_request_replay_and_strict_binding_expiry_are_enforced() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("replay-target");
    fs::write(&path, b"stable").unwrap();
    let original = read_request(
        root_identity(directory.path()),
        "replay-target",
        file_version(&path),
    );
    let original_observation = observation(&original);
    let mut replay = original.clone();
    replay.push(b' ');
    let replay_observation = observation(&replay);
    assert_ne!(
        original_observation.request_digest(),
        replay_observation.request_digest()
    );
    assert_eq!(
        original_observation.arguments_digest(),
        replay_observation.arguments_digest()
    );

    let expired = serde_json::to_vec(&json!({
        "operation": "Read",
        "binding": binding(expiry(-1)),
        "path": "replay-target",
        "root": root_identity(directory.path()),
        "expected": file_version(&path),
    }))
    .unwrap();
    assert!(helper_protocol::parse_helper_request(&expired).is_err());

    let too_large = vec![b' '; 16 * 1024 + 1];
    assert!(helper_protocol::parse_helper_request(&too_large).is_err());
}

#[test]
fn mismatched_root_unknown_duplicate_and_false_absence_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("strict-target");
    fs::write(&path, b"target").unwrap();
    let root = root_identity(directory.path());
    let valid = read_request(root.clone(), "strict-target", file_version(&path));
    let parsed = helper_protocol::parse_helper_request(&valid).unwrap();
    let workspace = fs::File::open(directory.path()).unwrap();
    helper_protocol::check_helper_target(&parsed, &workspace).unwrap();

    let mut wrong_root: Value = serde_json::from_slice(&valid).unwrap();
    wrong_root["root"]["inode"] = json!(0);
    let wrong_root = serde_json::to_vec(&wrong_root).unwrap();
    let wrong_root = helper_protocol::parse_helper_request(&wrong_root).unwrap();
    assert!(helper_protocol::check_helper_target(&wrong_root, &workspace).is_err());

    let mut unknown: Value = serde_json::from_slice(&valid).unwrap();
    unknown["unexpected"] = json!(true);
    assert!(helper_protocol::parse_helper_request(&serde_json::to_vec(&unknown).unwrap()).is_err());

    let mut duplicate = valid[..valid.len() - 1].to_vec();
    duplicate.extend_from_slice(b",\"path\":\"substituted\"}");
    assert!(helper_protocol::parse_helper_request(&duplicate).is_err());

    let (create, _) = create_request(root, "absent-target", b"");
    let mut create_value: Value = serde_json::from_slice(&create).unwrap();
    create_value["expected_absent"] = json!(false);
    let create = serde_json::to_vec(&create_value).unwrap();
    assert!(helper_protocol::parse_helper_request(&create).is_err());
    assert_ne!(
        helper_protocol::helper_request_digest(&valid),
        helper_protocol::helper_request_digest(&create)
    );
}
