use super::super::{
    NativeEnrollmentTupleV2, SignedInstalledReleaseVerificationErrorV2 as Error, UpdateMetadataV2,
    verify_exact_signed_installed_release_v2, verify_signed_update_metadata_v2,
};
use super::known_answers::{RELEASE_BINDING, metadata, trust};
use super::release_rejections::{canonical, requalify, resign_targets};

#[test]
fn every_resigned_release_field_changes_the_final_binding_not_the_inner_tuple() {
    let original = verify_signed_update_metadata_v2(&metadata(), &trust(), 100).unwrap();
    let original = original.qualified_release_candidate().unwrap();
    let mutations: [fn(&mut UpdateMetadataV2); 7] = [
        |value| value.targets.target.channel = "beta".into(),
        |value| value.targets.target.runtime_version = "0.2.0".into(),
        |value| value.targets.target.runtime_digest = "8".repeat(64),
        |value| value.targets.target.min_os = "14.0".into(),
        |value| value.targets.target.artifact_url = "https://updates.example.test/other.dmg".into(),
        |value| value.targets.target.artifact_size = 11,
        |value| value.targets.target.expires_at_unix_seconds = 501,
    ];
    for mutate in mutations {
        let mut alternate = metadata();
        mutate(&mut alternate);
        resign_targets(&mut alternate);
        let verified = verify_signed_update_metadata_v2(&alternate, &trust(), 100).unwrap();
        let candidate = verified.qualified_release_candidate().unwrap();
        assert_eq!(
            candidate.native_enrollment_tuple().inner_tuple_digest(),
            original.native_enrollment_tuple().inner_tuple_digest()
        );
        assert_ne!(
            candidate.release_binding_digest(),
            original.release_binding_digest()
        );
        assert_eq!(
            verify_exact_signed_installed_release_v2(
                &canonical(&alternate),
                &trust(),
                RELEASE_BINDING,
                100
            ),
            Err(Error::ReleaseBindingMismatch)
        );
    }
    let mut receipt = metadata();
    requalify(&mut receipt, "8", 99, 200);
    let verified = verify_signed_update_metadata_v2(&receipt, &trust(), 100).unwrap();
    let rebound = verified.qualified_release_candidate().unwrap();
    assert_eq!(
        rebound.native_enrollment_tuple().inner_tuple_digest(),
        original.native_enrollment_tuple().inner_tuple_digest()
    );
    assert_ne!(
        rebound.qualification_binding_digest(),
        original.qualification_binding_digest()
    );
    assert_ne!(
        rebound.release_binding_digest(),
        original.release_binding_digest()
    );
    assert_eq!(
        verify_exact_signed_installed_release_v2(
            &canonical(&receipt),
            &trust(),
            RELEASE_BINDING,
            100,
        ),
        Err(Error::ReleaseBindingMismatch)
    );
}

#[test]
fn resigned_swapped_writer_and_daemon_cannot_float_under_the_original_binding() {
    let mut swapped = metadata();
    let mut tuple = serde_json::to_value(&swapped.targets.target.native_enrollment_tuple).unwrap();
    let writer = tuple["writerSha256"].clone();
    tuple["writerSha256"] = tuple["daemonSha256"].clone();
    tuple["daemonSha256"] = writer;
    let target = swapped.targets.target.clone();
    let mut tuple: NativeEnrollmentTupleV2 = serde_json::from_value(tuple).unwrap();
    tuple.test_only_rebind_digest(&target);
    swapped.targets.target.native_enrollment_tuple = Some(tuple);
    requalify(&mut swapped, "9", 99, 200);
    assert!(verify_signed_update_metadata_v2(&swapped, &trust(), 100).is_ok());
    assert_eq!(
        verify_exact_signed_installed_release_v2(
            &canonical(&swapped),
            &trust(),
            RELEASE_BINDING,
            100,
        ),
        Err(Error::ReleaseBindingMismatch)
    );
}
