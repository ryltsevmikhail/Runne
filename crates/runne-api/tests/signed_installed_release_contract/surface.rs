use std::path::Path;

fn read(relative: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)).unwrap()
}

#[test]
fn exact_and_candidate_outputs_have_locked_nonserializable_derives() {
    let binding = read("src/provider_credential_enrollment/signed_installed_release/binding.rs");
    assert!(binding.contains(
        "#[derive(Clone, Debug, Eq, PartialEq)]\npub struct VerifiedSignedUpdateMetadataV2"
    ));
    assert!(binding.contains(
        "#[derive(Clone, Debug, Eq, PartialEq)]\npub struct VerifiedSignedNativeEnrollmentTupleV2"
    ));
    assert!(binding.contains(
        "#[derive(Clone, Debug, Eq, PartialEq)]\npub struct SignedInstalledReleaseCandidateV2"
    ));
    assert!(
        binding.contains(
            "#[derive(Debug, Eq, PartialEq)]\npub struct VerifiedSignedInstalledReleaseV2"
        )
    );
    for forbidden in [
        "impl Clone for VerifiedSignedInstalledReleaseV2",
        "Serialize for VerifiedSigned",
        "Deserialize for VerifiedSigned",
        "Default for VerifiedSigned",
        "From<SignedInstalledReleaseCandidateV2>",
    ] {
        assert!(
            !binding.contains(forbidden),
            "unexpected exact-output surface: {forbidden}"
        );
    }
}

#[test]
fn public_facade_has_only_the_two_locked_verifier_entrypoints() {
    let facade = read("src/provider_credential_enrollment/signed_installed_release.rs");
    let verification =
        read("src/provider_credential_enrollment/signed_installed_release/verification.rs");
    assert!(facade.contains("verify_exact_signed_installed_release_v2"));
    assert!(facade.contains("verify_signed_update_metadata_v2"));
    assert_eq!(
        verification
            .matches("pub fn verify_signed_update_metadata_v2(")
            .count(),
        1
    );
    assert_eq!(
        verification
            .matches("pub fn verify_exact_signed_installed_release_v2(")
            .count(),
        1
    );
    for forbidden in [
        "pub fn from_parts",
        "pub fn admit",
        "pub fn mint",
        "pub fn into_authority",
        "pub trait",
    ] {
        assert!(
            !verification.contains(forbidden),
            "unexpected public bridge: {forbidden}"
        );
    }
}

#[test]
fn compile_fail_matrix_is_attached_to_the_public_contract_module() {
    let contract = read("src/provider_credential_enrollment.rs");
    assert!(contract.matches("```compile_fail").count() >= 13);
    for witness in [
        "fields cannot be constructed directly",
        "exact output is move-only",
        "no Serde or Default bridge",
        "generic results cannot become exact",
        "no native-resource accessors",
        "cannot create authority",
        "no implementable raw-digest proof trait",
    ] {
        assert!(
            contract.contains(witness),
            "missing compile-fail witness: {witness}"
        );
    }
}
