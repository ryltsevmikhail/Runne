use super::super::{MeasuredNativeEnrollmentArtifactsV1, NativeEnrollmentTupleV2};

fn target() -> super::super::UpdateTargetV2 {
    let mut target = super::updater_enrollment_tuple::target();
    target.platform = "macos".into();
    target.arch = "arm64".into();
    target.min_os = "13.0".into();
    target.artifact_url = "https://updates.example.test/runne.dmg".into();
    target
}

fn tuple(target: &super::super::UpdateTargetV2) -> NativeEnrollmentTupleV2 {
    NativeEnrollmentTupleV2::new_macos(
        target.release_candidate_sha256.clone(),
        "c".repeat(64),
        "e".repeat(64),
        "f".repeat(64),
        target.bundle_sha256.clone(),
        "com.runne.desktop",
        "RUNNE12345",
        "3".repeat(40),
        "com.runne.writer",
        "RUNNE12345",
        "1".repeat(40),
        "com.runne.daemon",
        "RUNNE12345",
        "2".repeat(40),
        target,
    )
    .unwrap()
}

#[test]
fn macos_tuple_binds_distinct_exact_desktop_code_identity() {
    let macos = target();
    let tuple = tuple(&macos);
    let artifacts = MeasuredNativeEnrollmentArtifactsV1::new(
        "c".repeat(64),
        "e".repeat(64),
        "f".repeat(64),
        macos.bundle_sha256.clone(),
    )
    .unwrap();
    assert!(tuple.matches_installed(&macos, &artifacts));

    let mut replaced = serde_json::to_value(&tuple).unwrap();
    replaced["desktopCodeIdentity"]["cdhash"] = "4".repeat(40).into();
    let replaced = serde_json::from_value::<NativeEnrollmentTupleV2>(replaced).unwrap();
    assert!(!replaced.matches_installed(&macos, &artifacts));

    for (identifier, team, cdhash) in [
        ("", "RUNNE12345", "3".repeat(40)),
        ("com.runne.desktop", "runne12345", "3".repeat(40)),
        ("com.runne.desktop", "RUNNE12345", "3".repeat(39)),
        ("com.runne.writer", "RUNNE12345", "1".repeat(40)),
        ("com.runne.daemon", "RUNNE12345", "2".repeat(40)),
    ] {
        assert!(NativeEnrollmentTupleV2::new_macos(
            macos.release_candidate_sha256.clone(),
            "c".repeat(64),
            "e".repeat(64),
            "f".repeat(64),
            macos.bundle_sha256.clone(),
            identifier,
            team,
            cdhash,
            "com.runne.writer",
            "RUNNE12345",
            "1".repeat(40),
            "com.runne.daemon",
            "RUNNE12345",
            "2".repeat(40),
            &macos,
        )
        .is_err());
    }
}

#[test]
fn native_tuple_v2_rejects_legacy_or_substituted_schema_version() {
    let macos = target();
    let tuple = tuple(&macos);
    let mut legacy = serde_json::to_value(&tuple).unwrap();
    legacy.as_object_mut().unwrap().remove("schemaVersion");
    assert!(serde_json::from_value::<NativeEnrollmentTupleV2>(legacy).is_err());

    let mut substituted = serde_json::to_value(tuple).unwrap();
    substituted["schemaVersion"] = 1.into();
    let substituted = serde_json::from_value::<NativeEnrollmentTupleV2>(substituted).unwrap();
    let artifacts = MeasuredNativeEnrollmentArtifactsV1::new(
        "c".repeat(64),
        "e".repeat(64),
        "f".repeat(64),
        macos.bundle_sha256.clone(),
    )
    .unwrap();
    assert!(!substituted.matches_installed(&macos, &artifacts));
}
