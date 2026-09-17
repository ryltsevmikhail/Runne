use runne_api::{
    MacOsCodeIdentityExpectationV1, QualificationBootstrapClientArtifactV1,
    QualificationBootstrapClientV1, RunBinding,
};

use super::{VerifiedQualificationBootstrapClientPins, mint_after_installed_measurement};
use crate::{NativeEnrollmentTupleV3, UpdateTargetV2, VerifiedUpdateV2};

fn fixture() -> (UpdateTargetV2, NativeEnrollmentTupleV3) {
    let mut target = crate::tests::updater_enrollment_macos_identity::target();
    target.native_enrollment_tuple = None;
    let measured = crate::tests::updater_enrollment_v3_fixture::macos_tuple_v3(&target, '4');
    target.native_enrollment_tuple_v3 = Some(measured.clone());
    let verified = verify(&target);
    let tuple = verified.native_enrollment_tuple_v3().unwrap();
    let artifact = |identifier: &str, cdhash: char, digest: char| {
        QualificationBootstrapClientArtifactV1::new(
            MacOsCodeIdentityExpectationV1::new(
                identifier,
                "758F9Z45SR",
                cdhash.to_string().repeat(40),
            )
            .unwrap(),
            digest.to_string().repeat(64),
        )
        .unwrap()
    };
    target.qualification_bootstrap_client_v1 = Some(
        QualificationBootstrapClientV1::new(
            tuple.desktop_identity().clone(),
            tuple.daemon_identity().clone(),
            artifact("com.runne.qualification-gui-executor", 'a', 'a'),
            artifact("com.runne.qualification-root-service", 'b', 'b'),
            "f".repeat(64),
        )
        .unwrap(),
    );
    (target, measured)
}

fn verify(target: &UpdateTargetV2) -> VerifiedUpdateV2 {
    crate::tests::updater_enrollment_macos_identity::verify_target(target).unwrap()
}

fn pins(
    verified: &VerifiedUpdateV2,
    measured: &NativeEnrollmentTupleV3,
) -> VerifiedQualificationBootstrapClientPins {
    let admission = verified.admit_native_enrollment_v3(measured).unwrap();
    assert!(
        admission.bootstrap_client_pins.is_none(),
        "raw public admission never creates transport authority"
    );
    mint_after_installed_measurement(verified, &admission).unwrap()
}

fn binding(
    pins: &VerifiedQualificationBootstrapClientPins,
    manifest: [u8; 32],
    profile: [u8; 32],
) -> RunBinding {
    RunBinding::new(
        "run-42",
        [1; 20],
        pins.candidate,
        pins.raw_tuple,
        [2; 32],
        manifest,
        profile,
    )
    .unwrap()
}

#[test]
fn raw_admission_cannot_mint_and_pinned_binding_rejects_manifest_profile_and_expiry() {
    let (target, measured) = fixture();
    let verified = verify(&target);
    let mut pins = pins(&verified, &measured);
    let good = binding(&pins, pins.manifest, [0xff; 32]);
    assert!(
        !pins.matches_prepared_binding(&good),
        "historical signed fixture is expired"
    );
    // Test-local clock fixture only; no production expiry override exists.
    pins.expires_at = u64::MAX;
    assert!(pins.matches_prepared_binding(&good));
    assert!(!pins.matches_prepared_binding(&binding(&pins, [7; 32], [0xff; 32])));
    assert!(!pins.matches_prepared_binding(&binding(&pins, pins.manifest, [7; 32])));
    let altered_candidate = RunBinding::new(
        "run-42",
        [1; 20],
        [7; 32],
        pins.raw_tuple,
        [2; 32],
        pins.manifest,
        [0xff; 32],
    )
    .unwrap();
    let altered_raw = RunBinding::new(
        "run-42",
        [1; 20],
        pins.candidate,
        [7; 32],
        [2; 32],
        pins.manifest,
        [0xff; 32],
    )
    .unwrap();
    assert!(!pins.matches_prepared_binding(&altered_candidate));
    assert!(!pins.matches_prepared_binding(&altered_raw));
}

#[test]
fn qualified_or_different_generation_admission_cannot_attach_bootstrap_pins() {
    let (mut target, measured) = fixture();
    let verified = verify(&target);
    let mut admission = verified.admit_native_enrollment_v3(&measured).unwrap();
    admission.installed_generation += 1;
    assert!(mint_after_installed_measurement(&verified, &admission).is_none());
    let row = crate::NativeEnrollmentQualificationRowV1::new_v3(
        &target,
        &measured,
        "9".repeat(64),
        99,
        200,
    )
    .unwrap();
    target.native_enrollment_tuple_v3 =
        Some(measured.clone().with_qualification(&target, row).unwrap());
    let qualified = verify(&target);
    let admission = qualified.admit_native_enrollment_v3(&measured).unwrap();
    assert!(mint_after_installed_measurement(&qualified, &admission).is_none());
}

#[test]
fn resigned_sibling_change_is_visible_in_retained_manifest_even_with_same_raw_tuple() {
    let (target, measured) = fixture();
    let first = pins(&verify(&target), &measured);
    let mut encoded = serde_json::to_value(&target).unwrap();
    encoded["qualificationBootstrapClientV1"]["qualificationProfileSha256"] = "e".repeat(64).into();
    let second_target = serde_json::from_value(encoded).unwrap();
    let second = pins(&verify(&second_target), &measured);
    assert_eq!(first.raw_tuple, second.raw_tuple);
    assert_ne!(first.manifest, second.manifest);
    assert_ne!(first, second);
}
