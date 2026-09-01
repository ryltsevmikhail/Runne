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
        binding.contains("#[derive(Eq, PartialEq)]\npub struct VerifiedSignedInstalledReleaseV2")
    );
    for forbidden in [
        "impl Clone for VerifiedSignedInstalledReleaseV2",
        "Serialize for VerifiedSigned",
        "Deserialize for VerifiedSigned",
        "Default for VerifiedSigned",
        "From<SignedInstalledReleaseCandidateV2>",
        "#[derive(Debug, Eq, PartialEq)]\npub struct VerifiedSignedInstalledReleaseV2",
    ] {
        assert!(
            !binding.contains(forbidden),
            "unexpected exact-output surface: {forbidden}"
        );
    }
}

#[test]
fn exact_output_exposes_only_hidden_boolean_matches_and_one_opaque_projection() {
    let matchers =
        read("src/provider_credential_enrollment/signed_installed_release/binding/matchers.rs");
    let production = matchers.split("#[cfg(test)]").next().unwrap();

    for name in [
        "matches_desktop_digest",
        "matches_writer_digest",
        "matches_daemon_digest",
        "matches_contract_digest",
        "matches_release_binding",
        "matches_desktop_code_identity",
        "matches_writer_code_identity",
        "matches_daemon_code_identity",
    ] {
        assert_eq!(
            production.matches(&format!("pub fn {name}(")).count(),
            1,
            "missing exact matcher {name}"
        );
    }
    assert_eq!(
        production
            .matches("pub fn release_binding_matcher(")
            .count(),
        1
    );
    assert_eq!(production.matches("pub fn ").count(), 9);
    assert_eq!(production.matches("#[doc(hidden)]").count(), 9);
    for forbidden in [
        "pub fn signed_candidate",
        "pub fn candidate",
        "pub fn metadata",
        "pub fn release_binding_digest",
        "pub fn digest",
        "pub fn bytes",
        "pub fn raw",
        "pub fn from_parts",
        "pub fn admit",
        "pub fn mint",
        "pub fn into_authority",
        "pub trait",
    ] {
        assert!(
            !production.contains(forbidden),
            "exact output exposes forbidden surface: {forbidden}"
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
