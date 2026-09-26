use super::*;
use std::{fs, os::unix::fs::symlink, path::PathBuf};

fn target() -> UpdateTargetV2 {
    UpdateTargetV2 {
        product_id: "runne".into(),
        version: "1.2.3".into(),
        platform: "linux".into(),
        arch: "x86_64".into(),
        artifact_sha256: "0".repeat(64),
        artifact_size: 0,
        artifact_url: "https://updates.example/runne.AppImage".into(),
        release_candidate_sha256: "1".repeat(64),
        min_os: "linux".into(),
        profile_id: "stable".into(),
        bundle_sha256: "2".repeat(64),
        runtime_version: "1.2.3".into(),
        runtime_digest: "3".repeat(64),
        channel: "stable".into(),
        published_at_unix_seconds: 1,
        expires_at_unix_seconds: 999,
        rollback_floor: "1.0.0".into(),
        native_enrollment_tuple: None,
        native_enrollment_tuple_v3: None,
        qualification_bootstrap_client_v1: None,
    }
}

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let app = temp.path().join("Runne.AppDir");
    let paths = [
        "usr/bin/runne-desktop",
        "usr/bin/runne",
        "usr/bin/runned",
        "usr/lib/Runne/contracts/gocode-ui-client-3/bundle.json",
    ];
    for (i, rel) in paths.iter().enumerate() {
        let path = app.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, format!("file-{i}")).unwrap();
    }
    let artifact = temp.path().join("runne.AppImage");
    fs::write(&artifact, b"appimage-content").unwrap();
    let receipt = temp.path().join("qualification.json");
    let digest = |bytes: &[u8]| hex::encode(Sha256::digest(bytes));
    fs::write(
        receipt.with_extension("log"),
        b"qualification check output\n",
    )
    .unwrap();
    fs::write(
        &receipt,
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1,
            "artifactSha256": digest(b"appimage-content"),
            "releaseCandidateSha256": "1".repeat(64),
            "desktopSha256": digest(b"file-0"),
            "cliSha256": digest(b"file-1"),
            "daemonSha256": digest(b"file-2"),
            "contractSha256": digest(b"file-3"),
            "checks": ["desktop-library-tests", "appimage-component-match"],
            "checkCommands": ["cargo test -p runne-platform-desktop --lib", "AppImage extraction and required-component cmp checks"],
            "checkExitStatuses": [0, 0],
            "checkLogSha256": digest(b"qualification check output\n"),
            "qualifiedAtUnixSeconds": 100,
            "expiresAtUnixSeconds": 200
        }))
        .unwrap(),
    )
    .unwrap();
    (temp, app, artifact, receipt)
}

#[test]
fn rejects_unstructured_or_mismatched_qualification_receipts() {
    let (temp, app, artifact, receipt) = fixture();
    fs::write(&receipt, b"receipt-content").unwrap();
    assert!(
        produce_linux_native_enrollment_tuple_v2(
            &app,
            &artifact,
            &receipt,
            &temp.path().join("bad.json"),
            target(),
            100,
            200
        )
        .is_err()
    );

    let (temp, app, artifact, receipt) = fixture();
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&receipt).unwrap()).unwrap();
    value["artifactSha256"] = "f".repeat(64).into();
    fs::write(&receipt, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(
        produce_linux_native_enrollment_tuple_v2(
            &app,
            &artifact,
            &receipt,
            &temp.path().join("bad.json"),
            target(),
            100,
            200
        )
        .is_err()
    );
}

#[test]
fn measures_staged_appdir_artifact_receipt_and_create_new_json() {
    let (temp, app, artifact, receipt) = fixture();
    let output = temp.path().join("tuple.json");
    let produced = produce_linux_native_enrollment_tuple_v2(
        &app,
        &artifact,
        &receipt,
        &output,
        target(),
        100,
        200,
    )
    .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(json["schemaVersion"], 1);
    assert_eq!(
        json["target"]["artifactSha256"],
        hex::encode(Sha256::digest(b"appimage-content"))
    );
    assert_eq!(
        json["target"]["bundleSha256"],
        hex::encode(Sha256::digest(b"file-3"))
    );
    assert_eq!(
        json["target"]["runtimeDigest"],
        hex::encode(Sha256::digest(b"file-2"))
    );
    assert!(json["tuple"]["nativeEnrollmentQualification"].is_object());
    assert!(
        produce_linux_native_enrollment_tuple_v2(
            &app,
            &artifact,
            &receipt,
            &output,
            target(),
            100,
            200
        )
        .is_err()
    );
    assert_eq!(
        produced.target.artifact_size,
        b"appimage-content".len() as u64
    );
}

#[test]
fn rejects_symlinked_staged_file_and_artifact() {
    let (temp, app, artifact, receipt) = fixture();
    let bad = app.join("usr/bin/runned");
    fs::remove_file(&bad).unwrap();
    symlink("runne", &bad).unwrap();
    assert!(
        produce_linux_native_enrollment_tuple_v2(
            &app,
            &artifact,
            &receipt,
            &temp.path().join("x"),
            target(),
            100,
            200
        )
        .is_err()
    );
    let fresh = fixture();
    let link = temp.path().join("link.AppImage");
    symlink(&artifact, &link).unwrap();
    assert!(
        produce_linux_native_enrollment_tuple_v2(
            &fresh.1,
            &link,
            &fresh.3,
            &temp.path().join("y"),
            target(),
            100,
            200
        )
        .is_err()
    );
}
