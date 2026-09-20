//! Profile-manipulation scenarios for the read-only `task` command: a genuine
//! transport failure (dead endpoint) and a forged bootstrap secret that must
//! fail closed without disclosing secret material.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use crate::support::{
    exit_code, parse_json_error_envelope, run_cli, start_test_daemon, stop_daemon,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn task_list_against_a_dead_endpoint_is_runtime_unavailable() {
    let mut daemon = start_test_daemon().await;
    // Graceful shutdown deletes the published profile and secret
    // (PublishedClientProfileV3::Drop), so a copy of the fixture profile with
    // its own secret and a closed loopback port provides the genuine transport
    // failure: connection refused before any HTTP exchange.
    let copy_directory = tempfile::tempdir().expect("copy directory");
    fs::set_permissions(copy_directory.path(), fs::Permissions::from_mode(0o700))
        .expect("secure copy directory");
    let profile_copy = copy_directory.path().join("client-profile.json");
    let mut profile_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&daemon.profile).expect("read profile"))
            .expect("profile JSON");
    let secret_copy = copy_directory.path().join("bootstrap.secret");
    fs::copy(
        profile_json["bootstrapSecretPath"]
            .as_str()
            .expect("bootstrapSecretPath"),
        &secret_copy,
    )
    .expect("copy bootstrap secret");
    fs::set_permissions(&secret_copy, fs::Permissions::from_mode(0o600))
        .expect("secure secret copy");
    profile_json["bootstrapSecretPath"] =
        serde_json::Value::String(secret_copy.to_str().expect("secret path").to_owned());
    profile_json["endpoint"] = serde_json::Value::String("https://127.0.0.1:9".to_owned());
    fs::write(
        &profile_copy,
        serde_json::to_vec(&profile_json).expect("serialize profile copy"),
    )
    .expect("write profile copy");
    fs::set_permissions(&profile_copy, fs::Permissions::from_mode(0o600))
        .expect("secure profile copy");
    let profile_copy_arg = profile_copy.to_str().expect("profile copy path").to_owned();

    let output = run_cli(&[
        "--format",
        "json",
        "--profile",
        &profile_copy_arg,
        "task",
        "list",
    ])
    .await;
    assert_eq!(exit_code(&output), 1);
    assert!(output.stdout.is_empty());
    let envelope = parse_json_error_envelope(&output, "dead endpoint");
    assert_eq!(envelope["error"]["code"], "runtime_unavailable");

    stop_daemon(&mut daemon).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forged_bootstrap_secret_fails_closed_without_disclosure() {
    let mut daemon = start_test_daemon().await;
    let profile_arg = daemon.profile.to_str().expect("profile path").to_owned();
    let profile_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&daemon.profile).expect("read profile"))
            .expect("profile JSON");
    let secret_path = PathBuf::from(
        profile_json["bootstrapSecretPath"]
            .as_str()
            .expect("bootstrapSecretPath"),
    );
    let mut forged = fs::read(&secret_path).expect("read bootstrap secret");
    assert_eq!(forged.len(), 32, "raw 32-byte bootstrap secret");
    forged[0] ^= 0xff;
    fs::write(&secret_path, &forged).expect("overwrite bootstrap secret");
    let mode = fs::metadata(&secret_path)
        .expect("secret metadata")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "secret stays owner-only");

    let output = run_cli(&[
        "--format",
        "json",
        "--profile",
        &profile_arg,
        "task",
        "list",
    ])
    .await;
    assert_eq!(exit_code(&output), 1, "forged proof must not authenticate");
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr.clone()).expect("UTF-8 stderr");
    let envelope = parse_json_error_envelope(&output, "forged secret");
    assert_eq!(
        envelope["error"]["code"], "api_error",
        "observed: unauthorized handshake maps to api_error (401)"
    );
    assert!(!stderr.is_empty());
    assert!(!stderr.contains("secret"), "no secret material in stderr");

    stop_daemon(&mut daemon).await;
}
