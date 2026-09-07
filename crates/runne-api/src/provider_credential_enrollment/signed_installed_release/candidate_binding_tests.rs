use super::{UpdateTargetV2, VerifiedSignedInstalledReleaseV2};

const MAX_CANDIDATE_BINDING_BYTES: usize = 65_536;

fn target() -> UpdateTargetV2 {
    let (metadata, _, _) = super::tests::pinned_test_facts();
    let mut target = metadata.targets.target;
    target.native_enrollment_tuple = None;
    target.native_enrollment_tuple_v3 = None;
    target
}

fn exact_v3(mut target: UpdateTargetV2) -> VerifiedSignedInstalledReleaseV2 {
    let (mut metadata, trust, _) = super::tests::pinned_test_facts();
    target.native_enrollment_tuple = None;
    let tuple = super::tuple_v3_tests::tuple(&target);
    let qualification =
        super::NativeEnrollmentQualificationRowV1::new_v3(&target, &tuple, "a".repeat(64), 90, 200)
            .unwrap();
    target.native_enrollment_tuple_v3 =
        Some(tuple.with_qualification(&target, qualification).unwrap());
    metadata.targets.target = target;
    super::tuple_v3_tests::resign_targets(&mut metadata);
    let verified = super::verify_signed_update_metadata_v2(&metadata, &trust, 100).unwrap();
    let expected = verified
        .qualified_release_candidate_v3()
        .unwrap()
        .release_binding_digest();
    super::binding::exact(verified, expected).unwrap()
}

fn exact_v2() -> VerifiedSignedInstalledReleaseV2 {
    let (metadata, trust, expected) = super::tests::pinned_test_facts();
    let verified = super::verify_signed_update_metadata_v2(&metadata, &trust, 100).unwrap();
    super::binding::exact(verified, expected).unwrap()
}

fn quoted(value: &str) -> String {
    serde_json::to_string(value).unwrap()
}

fn canonical(target: &UpdateTargetV2) -> Vec<u8> {
    format!(
        concat!(
            "{{\"arch\":{},\"platform\":{},\"productId\":{},",
            "\"profileId\":{},\"releaseCandidateSha256\":{},",
            "\"schemaVersion\":1,\"version\":{}}}"
        ),
        quoted(&target.arch),
        quoted(&target.platform),
        quoted(&target.product_id),
        quoted(&target.profile_id),
        quoted(&target.release_candidate_sha256),
        quoted(&target.version),
    )
    .into_bytes()
}

#[test]
fn exact_v3_candidate_binding_matches_but_v2_never_does() {
    let target = target();
    let binding = canonical(&target);
    assert!(exact_v3(target).matches_native_enrollment_v3_candidate_binding(&binding));
    assert!(!exact_v2().matches_native_enrollment_v3_candidate_binding(&binding));
}

#[test]
fn every_retained_target_field_and_schema_are_required() {
    let target = target();
    let release = exact_v3(target.clone());
    for name in [
        "arch",
        "platform",
        "product",
        "profile",
        "candidate",
        "version",
    ] {
        let mut candidate = target.clone();
        match name {
            "arch" => candidate.arch = "x64".into(),
            "platform" => candidate.platform = "linux".into(),
            "product" => candidate.product_id = "other".into(),
            "profile" => candidate.profile_id = "other/1".into(),
            "candidate" => candidate.release_candidate_sha256 = "e".repeat(64),
            "version" => candidate.version = "9.9.9".into(),
            _ => unreachable!(),
        }
        assert!(
            !release.matches_native_enrollment_v3_candidate_binding(&canonical(&candidate)),
            "accepted changed {name}"
        );
    }
    let schema_two = String::from_utf8(canonical(&target))
        .unwrap()
        .replace("\"schemaVersion\":1", "\"schemaVersion\":2");
    assert!(!release.matches_native_enrollment_v3_candidate_binding(schema_two.as_bytes()));
}

#[test]
fn candidate_binding_requires_strict_canonical_bounded_json() {
    let target = target();
    let release = exact_v3(target.clone());
    let valid = String::from_utf8(canonical(&target)).unwrap();
    let duplicate = valid.replacen("\"arch\":", "\"arch\":\"arm64\",\"arch\":", 1);
    let mut value: serde_json::Value = serde_json::from_str(&valid).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("unknown".into(), true.into());
    let unknown = serde_json::to_vec(&value).unwrap();
    value.as_object_mut().unwrap().remove("unknown");
    value.as_object_mut().unwrap().remove("version");
    let missing = serde_json::to_vec(&value).unwrap();
    let noncanonical = valid.replacen(
        "{\"arch\":\"arm64\",\"platform\":\"macos\"",
        "{\"platform\":\"macos\",\"arch\":\"arm64\"",
        1,
    );
    let invalid_bindings = [
        duplicate.into_bytes(),
        unknown,
        missing,
        format!("{valid} ").into_bytes(),
        format!("{valid}x").into_bytes(),
        noncanonical.into_bytes(),
        vec![0xff],
        b"{".to_vec(),
    ];
    for invalid in &invalid_bindings {
        assert!(!release.matches_native_enrollment_v3_candidate_binding(invalid));
    }
    assert!(
        !release.matches_native_enrollment_v3_candidate_binding(&vec![
            b' ';
            MAX_CANDIDATE_BINDING_BYTES
                + 1
        ])
    );
}

#[test]
fn exact_release_rejects_cross_release_target_substitution() {
    let first = target();
    let mut second = first.clone();
    second.version = "2.0.0".into();
    assert_eq!(
        first.release_candidate_sha256,
        second.release_candidate_sha256
    );
    let first_release = exact_v3(first.clone());
    let second_release = exact_v3(second.clone());
    assert!(!first_release.matches_native_enrollment_v3_candidate_binding(&canonical(&second)));
    assert!(!second_release.matches_native_enrollment_v3_candidate_binding(&canonical(&first)));
}

#[test]
fn canonical_binding_at_exact_size_limit_is_accepted() {
    let mut target = target();
    target.version.clear();
    let base = canonical(&target).len();
    target.version = "v".repeat(MAX_CANDIDATE_BINDING_BYTES - base);
    let binding = canonical(&target);
    assert_eq!(binding.len(), MAX_CANDIDATE_BINDING_BYTES);
    assert!(exact_v3(target).matches_native_enrollment_v3_candidate_binding(&binding));
}
