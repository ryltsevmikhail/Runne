use super::super::{MeasuredNativeEnrollmentArtifactsV1, NativeEnrollmentTupleV1, UpdateTargetV2};

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
