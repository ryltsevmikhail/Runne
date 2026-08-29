use super::super::{MeasuredNativeEnrollmentArtifactsV1, NativeEnrollmentTupleV1, UpdateTargetV2};
use sha2::{Digest as _, Sha256};

pub(super) fn target() -> UpdateTargetV2 {
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
