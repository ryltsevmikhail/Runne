use super::{NativeEnrollmentQualificationRowV1, NativeEnrollmentTupleV2, UpdateTargetV2};

fn target(platform: &str, arch: &str, artifact_url: &str) -> UpdateTargetV2 {
    UpdateTargetV2 {
        product_id: "com.runne.desktop".into(),
        version: "1.2.0".into(),
        platform: platform.into(),
        arch: arch.into(),
        artifact_sha256: "1".repeat(64),
        artifact_size: 1,
        artifact_url: artifact_url.into(),
        release_candidate_sha256: "2".repeat(64),
        min_os: "ubuntu-22.04".into(),
        profile_id: "profile".into(),
        bundle_sha256: "6".repeat(64),
        runtime_version: "0.1.0".into(),
        runtime_digest: "5".repeat(64),
        channel: "stable".into(),
        published_at_unix_seconds: 90,
        expires_at_unix_seconds: 200,
        rollback_floor: "1.0.0".into(),
        native_enrollment_tuple: None,
        native_enrollment_tuple_v3: None,
        qualification_bootstrap_client_v1: None,
    }
}

fn tuple_for(target: &UpdateTargetV2) -> NativeEnrollmentTupleV2 {
    NativeEnrollmentTupleV2::new(
        target.release_candidate_sha256.clone(),
        "3".repeat(64),
        "4".repeat(64),
        target.runtime_digest.clone(),
        target.bundle_sha256.clone(),
        target,
    )
    .unwrap()
}

#[test]
fn linux_x86_64_v2_qualification_accepts_only_appimage_and_deb_artifacts() {
    for (url, _kind) in [
        ("https://updates.example/runne.AppImage", "appimage"),
        ("https://updates.example/runne.deb?channel=stable", "deb"),
    ] {
        let target = target("linux", "x86_64", url);
        let tuple = tuple_for(&target);
        let row =
            NativeEnrollmentQualificationRowV1::new(&target, &tuple, "7".repeat(64), 100, 180)
                .unwrap();
        assert!(tuple.with_qualification(&target, row).is_ok());
    }
}

#[test]
fn linux_qualification_rejects_wrong_platform_architecture_and_suffix() {
    for target in [
        target("windows", "x86_64", "https://updates.example/runne.deb"),
        target("linux", "aarch64", "https://updates.example/runne.AppImage"),
        target("linux", "x86_64", "https://updates.example/runne.tar.zst"),
    ] {
        let tuple = tuple_for(&target);
        assert!(
            NativeEnrollmentQualificationRowV1::new(&target, &tuple, "7".repeat(64), 100, 180,)
                .is_err()
        );
    }
}

#[test]
fn linux_qualification_rejects_tampered_row_platform_or_package_kind() {
    let target = target("linux", "x86_64", "https://updates.example/runne.AppImage");
    let tuple = tuple_for(&target);
    let row =
        NativeEnrollmentQualificationRowV1::new(&target, &tuple, "7".repeat(64), 100, 180).unwrap();
    for (field, value) in [("platform", "macos"), ("packageKind", "deb")] {
        let mut encoded = serde_json::to_value(&row).unwrap();
        encoded[field] = value.into();
        let tampered: NativeEnrollmentQualificationRowV1 = serde_json::from_value(encoded).unwrap();
        assert!(tuple.clone().with_qualification(&target, tampered).is_err());
    }
}
