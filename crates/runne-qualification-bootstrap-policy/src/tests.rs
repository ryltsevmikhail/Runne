use std::fs;
#[cfg(target_os = "macos")]
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _, symlink};
#[cfg(target_os = "macos")]
use std::process::Command;

use serde_json::json;
use tempfile::TempDir;

use super::*;

fn fixture() -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().unwrap();
    #[cfg(target_os = "macos")]
    fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let policy_dir = dir.path().join("policy");
    #[cfg(target_os = "macos")]
    fs::create_dir(&policy_dir).unwrap();
    #[cfg(target_os = "macos")]
    fs::set_permissions(&policy_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let policy = policy_dir.join("bootstrap-policy.json");
    fs::write(&policy, bytes()).unwrap();
    #[cfg(target_os = "macos")]
    fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o600)).unwrap();
    (dir, policy)
}
fn bytes() -> Vec<u8> {
    let wire: WirePolicy = serde_json::from_value(json!({
        "schema_version":SCHEMA_VERSION,"source_revision":"11".repeat(20),"workflow_run_id":"run_42",
        "candidate_sha256":"22".repeat(32),"raw_v3_tuple_sha256":"33".repeat(32),"namespace_sha256":"44".repeat(32),"manifest_sha256":"55".repeat(32),"profile_sha256":"66".repeat(32),"package_root":"/Applications/Runne.app",
        "desktop":artifact_json("com.runne.desktop","77"),"runtime":artifact_json("com.runne.runtime","88"),"executor":artifact_json("com.runne.executor","99"),"root_consume":artifact_json("com.runne.root","aa"),
        "login_euid":501,"login_audit_session":1,"root_audit_session":0,"not_before":1,"expires_at":2,"max_run_duration_seconds":1,
        "context_public_key":"bb".repeat(32),"context_key_id":digest("bb"),"fault_public_key":"cc".repeat(32),"fault_key_id":digest("cc")
    })).unwrap();
    serde_json::to_vec(&wire).unwrap()
}
fn wire() -> WirePolicy {
    serde_json::from_slice(&bytes()).unwrap()
}
fn artifact_json(identifier: &str, image: &str) -> serde_json::Value {
    json!({"identifier":identifier,"team_identifier":"758F9Z45SR","cdhash":"a".repeat(40),"image_sha256":image.repeat(32)})
}
fn digest(byte: &str) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(hex::decode(byte.repeat(32)).unwrap()))
}
#[cfg(target_os = "macos")]
fn load(
    path: &std::path::Path,
) -> Result<RetainedQualificationBootstrapPolicy, QualificationBootstrapPolicyError> {
    macos::load_fixture(path, fs::metadata(path).unwrap().uid())
}
#[cfg(target_os = "macos")]
fn chmod_acl(arguments: &[&str], path: &std::path::Path) {
    assert!(
        Command::new("/bin/chmod")
            .args(arguments)
            .arg(path)
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn accepts_canonical_private_fixture_and_exposes_pins() {
    #[cfg(target_os = "macos")]
    {
        let (_dir, path) = fixture();
        let policy = load(&path).unwrap();
        assert_eq!(policy.policy().workflow_run_id(), "run_42");
        assert!(policy.policy().valid_at(1));
        assert!(policy.revalidate().is_ok());
    }
}
#[test]
fn rejects_noncanonical_malformed_paths_and_invalid_times() {
    for bad in [
        b"{}".as_slice(),
        b"{\"schema_version\":\"runne/qualification-bootstrap-policy/v1\"}".as_slice(),
        b"{} \n".as_slice(),
    ] {
        assert!(decode(bad).is_err());
    }
    for path in ["/a//b", "/a/./b", "/a/../b", "/a/", "/a\0b"] {
        let mut value = wire();
        value.package_root = path.into();
        assert!(decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let mut value = wire();
    value.expires_at = 1;
    assert!(decode(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut value = wire();
    value.expires_at = 3;
    value.max_run_duration_seconds = 3;
    assert!(decode(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut value = wire();
    value.root_audit_session = 1;
    assert!(decode(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut value = wire();
    value.login_audit_session = i32::MAX;
    assert!(decode(&serde_json::to_vec(&value).unwrap()).is_ok());
    let mut value = wire();
    value.desktop.cdhash = "0".repeat(40);
    assert!(decode(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut value: serde_json::Value = serde_json::from_slice(&bytes()).unwrap();
    value["login_audit_session"] = json!(i64::from(i32::MAX) + 1);
    assert!(serde_json::from_value::<WirePolicy>(value).is_err());
}
#[test]
fn rejects_duplicate_fields() {
    let text = String::from_utf8(bytes()).unwrap().replacen(
        "\"workflow_run_id\":\"run_42\"",
        "\"workflow_run_id\":\"run_42\",\"workflow_run_id\":\"run_43\"",
        1,
    );
    assert!(decode(text.as_bytes()).is_err());
}
#[test]
fn retained_path_rejects_content_replace_hardlink_symlink_and_mode_changes() {
    #[cfg(target_os = "macos")]
    {
        let (_dir, path) = fixture();
        let policy = load(&path).unwrap();
        fs::write(path.parent().unwrap().join("sibling"), b"sibling").unwrap();
        assert!(policy.revalidate().is_ok());
        let (_dir, path) = fixture();
        let policy = load(&path).unwrap();
        let parent = path.parent().unwrap();
        let old = parent.with_extension("old");
        fs::rename(parent, &old).unwrap();
        fs::create_dir(parent).unwrap();
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(&path, bytes()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(policy.revalidate().is_err());
        let (_dir, path) = fixture();
        let policy = load(&path).unwrap();
        let replacement = path.with_extension("new");
        fs::write(&replacement, bytes()).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(replacement, &path).unwrap();
        assert!(policy.revalidate().is_err());
        let (_dir, path) = fixture();
        let policy = load(&path).unwrap();
        fs::hard_link(&path, path.with_extension("link")).unwrap();
        assert!(policy.revalidate().is_err());
        let (_dir, path) = fixture();
        let policy = load(&path).unwrap();
        fs::remove_file(&path).unwrap();
        symlink("missing", &path).unwrap();
        assert!(policy.revalidate().is_err());
        let (_dir, path) = fixture();
        fs::remove_file(&path).unwrap();
        assert!(
            Command::new("/usr/bin/mkfifo")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        assert!(load(&path).is_err());
        let (_dir, path) = fixture();
        let policy = load(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(policy.revalidate().is_err());
        let (_dir, path) = fixture();
        let policy = load(&path).unwrap();
        fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o720)).unwrap();
        assert!(policy.revalidate().is_err());
        let (_dir, path) = fixture();
        chmod_acl(&["-N"], &path);
        let policy = load(&path).unwrap();
        chmod_acl(&["+a", "everyone deny write"], &path);
        assert!(policy.revalidate().is_err());
        chmod_acl(&["-N"], &path);
        let (_dir, path) = fixture();
        chmod_acl(&["-N"], path.parent().unwrap());
        let policy = load(&path).unwrap();
        chmod_acl(&["+a", "everyone deny delete"], path.parent().unwrap());
        assert!(policy.revalidate().is_err());
        chmod_acl(&["-N"], path.parent().unwrap());
    }
}
