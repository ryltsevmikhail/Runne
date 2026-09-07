use std::path::{Path, PathBuf};

#[path = "support/signed_release_surface_audit.rs"]
mod surface_audit;
#[path = "support/signed_release_surface_ingress.rs"]
mod surface_ingress;
#[path = "support/signed_release_surface_policy.rs"]
mod surface_policy;
#[path = "support/signed_release_surface_sources.rs"]
mod surface_sources;
#[path = "support/signed_release_surface_syntax.rs"]
mod surface_syntax;

fn source(path: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(path)).unwrap()
}

fn production_sources(directory: &Path, output: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            production_sources(&path, output);
        } else if path
            .extension()
            .is_some_and(|extension| extension == "rs" || extension == "inc")
        {
            output.push(path);
        }
    }
}

fn loaded_production_sources() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    surface_sources::load(&root).unwrap()
}

#[test]
fn candidate_binding_surface_is_narrow_and_has_one_owner() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/provider_credential_enrollment/signed_installed_release");
    let candidate = source(
        "src/provider_credential_enrollment/signed_installed_release/binding/candidate_binding.rs",
    );
    let binding = source("src/provider_credential_enrollment/signed_installed_release/binding.rs");
    let exact =
        source("src/provider_credential_enrollment/signed_installed_release/binding/exact.rs");
    let mut sources = vec![root.with_extension("rs")];
    production_sources(&root, &mut sources);
    let method = "pub fn matches_native_enrollment_v3_candidate_binding(";
    assert_eq!(
        sources
            .iter()
            .map(|path| std::fs::read_to_string(path)
                .unwrap()
                .matches(method)
                .count())
            .sum::<usize>(),
        1,
    );
    assert!(
        candidate
            .contains("#[doc(hidden)]\n    pub fn matches_native_enrollment_v3_candidate_binding(")
    );
    assert!(
        binding.contains(
            "candidate_binding_v3: Option<candidate_binding::VerifiedCandidateBindingV3>"
        )
    );
    assert!(exact.contains("VerifiedCandidateBindingV3::from_target(verified.target())"));
    assert!(exact.contains("candidate_v3.as_ref().map(|_| retained_target)"));
    assert_eq!(exact.matches("candidate_binding_v3,").count(), 1);
    for forbidden in [
        "pub struct VerifiedCandidateBindingV3",
        "pub fn from_target",
        "pub fn candidate_binding_v3",
        "pub fn target",
        "impl Serialize for VerifiedCandidateBindingV3",
        "Sha256",
    ] {
        assert!(
            !candidate.contains(forbidden),
            "candidate binding exposes or derives forbidden surface: {forbidden}"
        );
    }
    assert_eq!(
        surface_audit::audit(&loaded_production_sources()),
        Vec::<String>::new()
    );
}

#[test]
fn candidate_binding_parser_is_bounded_strict_and_canonical() {
    let candidate = source(
        "src/provider_credential_enrollment/signed_installed_release/binding/candidate_binding.rs",
    );
    let bound = candidate
        .find("canonical_binding.len() > MAX_CANDIDATE_BINDING_BYTES")
        .unwrap();
    let parse = candidate
        .find("serde_json::from_slice::<CandidateBindingV3>")
        .unwrap();
    assert!(
        bound < parse,
        "candidate resource is parsed before its size bound"
    );
    assert!(candidate.contains("const MAX_CANDIDATE_BINDING_BYTES: usize = 65_536;"));
    assert!(candidate.contains("#[serde(rename_all = \"camelCase\", deny_unknown_fields)]"));
    assert!(candidate.contains("serde_json::to_vec(&candidate)"));
    let shape = concat!(
        "struct CandidateBindingV3 {\n",
        "    arch: String,\n",
        "    platform: String,\n",
        "    product_id: String,\n",
        "    profile_id: String,\n",
        "    release_candidate_sha256: String,\n",
        "    schema_version: u32,\n",
        "    version: String,\n",
        "}"
    );
    assert!(candidate.contains(shape), "producer field order changed");
    assert!(candidate.contains("candidate.schema_version != 1"));
    assert!(candidate.contains("tuple.candidate_digest().ct_eq(&embedded_digest)"));
}

fn assert_mutation_rejected(path: &str, injected: &str, category: &str) {
    let mut sources = loaded_production_sources();
    sources.push((path.into(), injected.into()));
    let violations = surface_audit::audit(&sources);
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains(category)),
        "mutation was not rejected as {category}: {violations:?}"
    );
}

fn assert_replacement_rejected(path_suffix: &str, from: &str, to: &str, category: &str) {
    let mut sources = loaded_production_sources();
    let source = sources
        .iter_mut()
        .find(|(path, _)| path.ends_with(path_suffix))
        .unwrap();
    assert!(source.1.contains(from), "fixture target missing: {from}");
    source.1 = source.1.replacen(from, to, 1);
    let violations = surface_audit::audit(&sources);
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains(category)),
        "replacement was not rejected as {category}: {violations:?}"
    );
}

#[test]
fn structural_guard_rejects_alternate_getter_and_type_alias() {
    assert_mutation_rejected(
        "neighbor.rs",
        r#"
        type ExactAlias = crate::VerifiedSignedInstalledReleaseV2;
        impl ExactAlias { pub fn projection(&self) -> &str { "leak" } }
        "#,
        "exact-release method",
    );
}

#[test]
fn structural_guard_rejects_qualified_serde_trait_from_inc() {
    assert_mutation_rejected(
        "neighbor.inc",
        r#"
        impl serde::Serialize for crate::provider_credential_enrollment::
            signed_installed_release::binding::candidate_binding::VerifiedCandidateBindingV3 {
            fn serialize<S>(&self, _: S) -> Result<S::Ok, S::Error>
            where S: serde::Serializer { unimplemented!() }
        }
        "#,
        "projection trait impl",
    );
}

#[test]
fn structural_guard_rejects_projection_derive_alias_and_reexport() {
    let mut sources = loaded_production_sources();
    let candidate = sources
        .iter_mut()
        .find(|(path, _)| path.ends_with("binding/candidate_binding.rs"))
        .unwrap();
    candidate.1 = candidate.1.replacen(
        "#[derive(Eq, PartialEq)]",
        "#[derive(Eq, PartialEq, serde::Serialize)]",
        1,
    );
    let violations = surface_audit::audit(&sources);
    assert!(
        violations
            .iter()
            .any(|value| value.contains("projection derive"))
    );

    assert_mutation_rejected(
        "reexport.rs",
        "pub use crate::provider_credential_enrollment::signed_installed_release::binding::candidate_binding::VerifiedCandidateBindingV3 as PublicProjection;",
        "projection reexport",
    );
}

#[test]
fn structural_guard_rejects_visibility_fields_constructor_and_conversion() {
    assert_replacement_rejected(
        "binding/candidate_binding.rs",
        "pub(super) struct VerifiedCandidateBindingV3",
        "pub(crate) struct VerifiedCandidateBindingV3",
        "projection visibility",
    );
    assert_replacement_rejected(
        "binding/candidate_binding.rs",
        "    arch: String,",
        "    pub(super) arch: String,",
        "projection fields",
    );
    assert_mutation_rejected(
        "constructor.rs",
        r#"
        impl crate::provider_credential_enrollment::signed_installed_release::binding::
            candidate_binding::VerifiedCandidateBindingV3 {
            pub(super) fn from_target(target: &UpdateTargetV2) -> Self { unimplemented!() }
        }
        "#,
        "projection constructor ownership",
    );
    assert_mutation_rejected(
        "conversion.rs",
        r#"
        struct Neighbor;
        impl core::convert::From<crate::VerifiedSignedInstalledReleaseV2> for Neighbor {
            fn from(_: crate::VerifiedSignedInstalledReleaseV2) -> Self { Self }
        }
        "#,
        "exact-release conversion",
    );
}

#[test]
fn structural_guard_resolves_projection_alias_reexport_and_exact_serde() {
    assert_mutation_rejected(
        "aliases.rs",
        r#"
        type HiddenProjection = crate::provider_credential_enrollment::
            signed_installed_release::binding::candidate_binding::VerifiedCandidateBindingV3;
        pub use HiddenProjection as InnocentName;
        "#,
        "projection reexport",
    );
    assert_mutation_rejected(
        "serde.rs",
        r#"
        impl ::serde::Serialize for crate::VerifiedSignedInstalledReleaseV2 {
            fn serialize<S>(&self, _: S) -> Result<S::Ok, S::Error>
            where S: ::serde::Serializer { unimplemented!() }
        }
        "#,
        "exact-release trait impl",
    );
}

#[test]
fn structural_guard_does_not_hide_production_cfg_branches() {
    for cfg in ["not(test)", "any(test, feature = \"alternate\")"] {
        assert_mutation_rejected(
            "conditional.rs",
            &format!(
                "#[cfg({cfg})] impl crate::VerifiedSignedInstalledReleaseV2 {{ pub fn leak(&self) {{}} }}"
            ),
            "exact-release method",
        );
    }
}

#[test]
fn structural_guard_ignores_exact_test_only_items() {
    let mut sources = loaded_production_sources();
    sources.push((
        "test_only.rs".into(),
        "#[cfg(test)] impl crate::VerifiedSignedInstalledReleaseV2 { pub fn fixture(&self) {} }"
            .into(),
    ));
    assert_eq!(surface_audit::audit(&sources), Vec::<String>::new());
}
