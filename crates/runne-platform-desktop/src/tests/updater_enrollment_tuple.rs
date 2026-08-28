use super::super::{MeasuredNativeEnrollmentArtifactsV1, NativeEnrollmentTupleV1, UpdateTargetV2};
use sha2::{Digest as _, Sha256};

fn target() -> UpdateTargetV2 {
    UpdateTargetV2 {
        product_id: "com.runne.desktop".into(),
        version: "1.2.3".into(),
        platform: "linux".into(),
        arch: "x86_64".into(),
        artifact_sha256: "a".repeat(64),
        artifact_size: 10,
        artifact_url: "https://updates.example.test/runne.AppImage".into(),
        release_candidate_sha256: "d".repeat(64),
        min_os: "ubuntu-22.04".into(),
        profile_id: "gocode-ui-client/2".into(),
        bundle_sha256: "b".repeat(64),
        runtime_version: "0.1.0".into(),
        runtime_digest: "c".repeat(64),
        channel: "stable".into(),
        published_at_unix_seconds: 100,
        expires_at_unix_seconds: 500,
        rollback_floor: "1.0.0".into(),
        native_enrollment_tuple: None,
    }
}

fn macos_target() -> UpdateTargetV2 {
    let mut target = target();
    target.platform = "macos".into();
    target.arch = "arm64".into();
    target.min_os = "13.0".into();
    target.artifact_url = "https://updates.example.test/runne.dmg".into();
    target
}

fn legacy_tuple_digest(
    target: &UpdateTargetV2,
    writer: &str,
    daemon: &str,
    contract: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"gocode/native-enrollment-release-tuple/v1\0");
    for value in [
        target.release_candidate_sha256.as_str(),
        target.product_id.as_str(),
        target.version.as_str(),
        target.platform.as_str(),
        target.arch.as_str(),
        target.profile_id.as_str(),
        target.artifact_sha256.as_str(),
        writer,
        daemon,
        contract,
    ] {
        hasher.update(u32::try_from(value.len()).unwrap().to_be_bytes());
        hasher.update(value.as_bytes());
    }
    hex::encode(hasher.finalize())
}

#[test]
fn enrollment_tuple_rejects_missing_reused_and_swapped_role_artifacts() {
    let target = target();
    assert!(
        NativeEnrollmentTupleV1::new(
            target.release_candidate_sha256.clone(),
            String::new(),
            "f".repeat(64),
            "b".repeat(64),
            &target
        )
        .is_err()
    );

    let tuple = NativeEnrollmentTupleV1::new(
        target.release_candidate_sha256.clone(),
        "e".repeat(64),
        "f".repeat(64),
        target.bundle_sha256.clone(),
        &target,
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&tuple).unwrap()["tupleSha256"],
        legacy_tuple_digest(&target, &"e".repeat(64), &"f".repeat(64), &target.bundle_sha256)
    );
    assert!(
        MeasuredNativeEnrollmentArtifactsV1::new(
            target.artifact_sha256.clone(),
            "e".repeat(64),
            "f".repeat(64),
            target.bundle_sha256.clone(),
        )
        .is_ok_and(|artifacts| tuple.matches_installed(&target, &artifacts))
    );
    assert!(
        MeasuredNativeEnrollmentArtifactsV1::new(
            target.artifact_sha256.clone(),
            "f".repeat(64),
            "e".repeat(64),
            target.bundle_sha256.clone(),
        )
        .is_ok_and(|artifacts| !tuple.matches_installed(&target, &artifacts))
    );
    assert!(
        NativeEnrollmentTupleV1::new(
            target.release_candidate_sha256.clone(),
            "e".repeat(64),
            "e".repeat(64),
            target.bundle_sha256.clone(),
            &target,
        )
        .is_err()
    );
    assert!(
        NativeEnrollmentTupleV1::new(
            "c".repeat(64),
            "e".repeat(64),
            "f".repeat(64),
            target.bundle_sha256.clone(),
            &target,
        )
        .is_err()
    );
}

#[test]
fn exact_qualification_remeasures_regular_writer_before_launch() {
    let directory = tempfile::tempdir().unwrap();
    let writer = directory.path().join("runne");
    std::fs::write(&writer, b"measured writer").unwrap();
    let writer_digest = hex::encode(Sha256::digest(b"measured writer"));
    let target = target();
    let tuple = NativeEnrollmentTupleV1::new(
        target.release_candidate_sha256.clone(),
        writer_digest.clone(),
        "f".repeat(64),
        target.bundle_sha256.clone(),
        &target,
    )
    .unwrap();
    let artifacts = MeasuredNativeEnrollmentArtifactsV1::new(
        target.artifact_sha256.clone(),
        writer_digest,
        "f".repeat(64),
        target.bundle_sha256.clone(),
    )
    .unwrap();
    let qualified = tuple.qualify(&target, &artifacts);

    assert!(qualified.verified_writer(writer.clone()).is_ok());
    #[cfg(unix)]
    {
        let link = directory.path().join("runne-link");
        std::os::unix::fs::symlink(&writer, &link).unwrap();
        assert!(qualified.verified_writer(link).is_err());
    }
    std::fs::write(&writer, b"modified writer").unwrap();
    assert!(qualified.verified_writer(writer).is_err());
}

#[test]
fn macos_tuple_requires_exact_non_adhoc_writer_code_identity() {
    let macos = macos_target();
    assert!(
        NativeEnrollmentTupleV1::new(
            macos.release_candidate_sha256.clone(),
            "e".repeat(64),
            "f".repeat(64),
            macos.bundle_sha256.clone(),
            &macos,
        )
        .is_err()
    );
    let valid = || {
        NativeEnrollmentTupleV1::new_macos(
            macos.release_candidate_sha256.clone(),
            "e".repeat(64),
            "f".repeat(64),
            macos.bundle_sha256.clone(),
            "com.runne.writer",
            "RUNNE12345",
            "1".repeat(40),
            &macos,
        )
    };
    assert!(valid().is_ok());
    for (identifier, team, cdhash) in [
        ("com.runne.*", "RUNNE12345", "1".repeat(40)),
        ("com.runne.writer", "", "1".repeat(40)),
        ("com.runne.writer", "RUNNE12345", "1".repeat(39)),
        ("com.runne.writer", "runne12345", "1".repeat(40)),
    ] {
        assert!(
            NativeEnrollmentTupleV1::new_macos(
                macos.release_candidate_sha256.clone(),
                "e".repeat(64),
                "f".repeat(64),
                macos.bundle_sha256.clone(),
                identifier,
                team,
                cdhash,
                &macos,
            )
            .is_err()
        );
    }
    let linux = target();
    assert!(
        NativeEnrollmentTupleV1::new_macos(
            linux.release_candidate_sha256.clone(),
            "e".repeat(64),
            "f".repeat(64),
            linux.bundle_sha256.clone(),
            "com.runne.writer",
            "RUNNE12345",
            "1".repeat(40),
            &linux,
        )
        .is_err()
    );
}

#[test]
fn macos_code_identity_is_tuple_bound_and_has_no_generic_launch_fallback() {
    let directory = tempfile::tempdir().unwrap();
    let writer = directory.path().join("runne");
    std::fs::write(&writer, b"measured macos writer").unwrap();
    let writer_digest = hex::encode(Sha256::digest(b"measured macos writer"));
    let target = macos_target();
    let tuple = NativeEnrollmentTupleV1::new_macos(
        target.release_candidate_sha256.clone(),
        writer_digest.clone(),
        "f".repeat(64),
        target.bundle_sha256.clone(),
        "com.runne.writer",
        "RUNNE12345",
        "1".repeat(40),
        &target,
    )
    .unwrap();
    let artifacts = MeasuredNativeEnrollmentArtifactsV1::new(
        target.artifact_sha256.clone(),
        writer_digest.clone(),
        "f".repeat(64),
        target.bundle_sha256.clone(),
    )
    .unwrap();
    let qualified = tuple.qualify(&target, &artifacts);
    assert!(qualified.verified_writer(writer.clone()).is_err());
    let launch = qualified.verified_macos_writer(writer).unwrap();
    assert_eq!(
        launch.code_requirement(),
        "identifier \"com.runne.writer\" and anchor apple generic and certificate leaf[subject.OU] = \"RUNNE12345\" and cdhash H\"1111111111111111111111111111111111111111\""
    );

    let original: serde_json::Value = serde_json::to_value(&tuple).unwrap();
    let mut substituted = original.clone();
    substituted["writerCodeIdentity"]["cdhash"] = serde_json::Value::String("2".repeat(40));
    let substituted: NativeEnrollmentTupleV1 = serde_json::from_value(substituted).unwrap();
    assert_eq!(
        substituted.qualify(&target, &artifacts),
        super::super::NativeEnrollmentQualification::Unqualified
    );
    assert_ne!(
        original["tupleSha256"],
        serde_json::to_value(
            NativeEnrollmentTupleV1::new_macos(
                target.release_candidate_sha256.clone(),
                writer_digest,
                "f".repeat(64),
                target.bundle_sha256.clone(),
                "com.runne.writer",
                "RUNNE12345",
                "2".repeat(40),
                &target,
            )
            .unwrap()
        )
        .unwrap()["tupleSha256"]
    );
}
