use super::super::{
    MeasuredNativeEnrollmentArtifactsV1, NativeEnrollmentTupleV1, UpdateTargetV2,
};
use sha2::{Digest as _, Sha256};

fn target() -> UpdateTargetV2 {
    let mut target = super::updater_enrollment_tuple::target();
    target.platform = "macos".into();
    target.arch = "arm64".into();
    target.min_os = "13.0".into();
    target.artifact_url = "https://updates.example.test/runne.dmg".into();
    target
}

#[test]
fn macos_tuple_requires_exact_non_adhoc_writer_code_identity() {
    let macos = target();
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
            "com.runne.daemon",
            "RUNNE12345",
            "2".repeat(40),
            &macos,
        )
    };
    assert!(valid().is_ok());
    assert!(
        NativeEnrollmentTupleV1::new_macos(
            macos.release_candidate_sha256.clone(),
            "e".repeat(64),
            "f".repeat(64),
            macos.bundle_sha256.clone(),
            "com.runne.shared",
            "RUNNE12345",
            "1".repeat(40),
            "com.runne.shared",
            "RUNNE12345",
            "1".repeat(40),
            &macos,
        )
        .is_err()
    );
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
                "com.runne.daemon",
                "RUNNE12345",
                "2".repeat(40),
                &macos,
            )
            .is_err()
        );
    }
    let linux = super::updater_enrollment_tuple::target();
    assert!(
        NativeEnrollmentTupleV1::new_macos(
            linux.release_candidate_sha256.clone(),
            "e".repeat(64),
            "f".repeat(64),
            linux.bundle_sha256.clone(),
            "com.runne.writer",
            "RUNNE12345",
            "1".repeat(40),
            "com.runne.daemon",
            "RUNNE12345",
            "2".repeat(40),
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
    let target = target();
    let tuple = NativeEnrollmentTupleV1::new_macos(
        target.release_candidate_sha256.clone(),
        writer_digest.clone(),
        "f".repeat(64),
        target.bundle_sha256.clone(),
        "com.runne.writer",
        "RUNNE12345",
        "1".repeat(40),
        "com.runne.daemon",
        "RUNNE12345",
        "2".repeat(40),
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
                "com.runne.daemon",
                "RUNNE12345",
                "3".repeat(40),
                &target,
            )
            .unwrap()
        )
        .unwrap()["tupleSha256"]
    );
}

#[test]
fn macos_daemon_identity_is_required_and_tuple_bound() {
    let directory = tempfile::tempdir().unwrap();
    let writer = directory.path().join("runne");
    std::fs::write(&writer, b"measured macos writer").unwrap();
    let writer_digest = hex::encode(Sha256::digest(b"measured macos writer"));
    let target = target();
    let tuple = NativeEnrollmentTupleV1::new_macos(
        target.release_candidate_sha256.clone(),
        writer_digest.clone(),
        "f".repeat(64),
        target.bundle_sha256.clone(),
        "com.runne.writer",
        "RUNNE12345",
        "1".repeat(40),
        "com.runne.daemon",
        "RUNNE12345",
        "2".repeat(40),
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
    let launch = tuple
        .qualify(&target, &artifacts)
        .verified_macos_writer(writer)
        .unwrap();
    assert_eq!(launch.daemon_image_digest(), [0xff; 32]);
    assert!(launch.daemon_code_requirement().contains("com.runne.daemon"));

    let original = serde_json::to_value(&tuple).unwrap();
    let mut missing = original.clone();
    missing.as_object_mut().unwrap().remove("daemonCodeIdentity");
    let missing: NativeEnrollmentTupleV1 = serde_json::from_value(missing).unwrap();
    assert_eq!(
        missing.qualify(&target, &artifacts),
        super::super::NativeEnrollmentQualification::Unqualified
    );
    let mut substituted = original;
    substituted["daemonCodeIdentity"]["cdhash"] =
        serde_json::Value::String("3".repeat(40));
    let substituted: NativeEnrollmentTupleV1 = serde_json::from_value(substituted).unwrap();
    assert_eq!(
        substituted.qualify(&target, &artifacts),
        super::super::NativeEnrollmentQualification::Unqualified
    );
}
