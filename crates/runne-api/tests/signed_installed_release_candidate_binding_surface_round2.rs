use std::path::Path;

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

fn production_sources() -> Vec<(String, String)> {
    surface_sources::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src")).unwrap()
}

fn assert_rejected(extra: &[(&str, &str)], category: &str) {
    let mut sources = production_sources();
    sources.extend(
        extra
            .iter()
            .map(|(path, source)| ((*path).into(), (*source).into())),
    );
    let violations = surface_audit::audit(&sources);
    assert!(
        violations.iter().any(|value| value.contains(category)),
        "surface escaped {category}: {violations:?}"
    );
}

#[test]
fn rejects_raw_free_and_unrelated_helper_ingress_with_named_facade_export() {
    assert_rejected(
        &[
            (
                "binding/raw_helper.rs",
                r#"
                pub(super) fn observe(
                    release: &crate::VerifiedSignedInstalledReleaseV2,
                ) -> (&str, &str, &str, &str, &str, &str) { unimplemented!() }
                "#,
            ),
            (
                "signed_installed_release.rs",
                "pub use binding::raw_helper::observe as verified_release_details;",
            ),
        ],
        "exact-release ingress",
    );
    assert_rejected(
        &[(
            "binding/helper.rs",
            r#"
            pub struct Neighbor;
            impl Neighbor {
                pub(crate) fn inspect(
                    _: &crate::VerifiedSignedInstalledReleaseV2,
                ) -> String { unimplemented!() }
            }
            "#,
        )],
        "exact-release ingress",
    );
}

#[test]
fn follows_non_test_path_into_tests_named_source() {
    let directory = tempfile::tempdir().unwrap();
    let tests = directory.path().join("tests");
    std::fs::create_dir(&tests).unwrap();
    std::fs::write(
        directory.path().join("lib.rs"),
        "#[path = \"tests/leak_tests.rs\"] mod leak;",
    )
    .unwrap();
    std::fs::write(
        tests.join("leak_tests.rs"),
        "impl crate::VerifiedSignedInstalledReleaseV2 { pub fn leak(&self) -> &str { \"x\" } }",
    )
    .unwrap();
    let sources = surface_sources::load(directory.path()).unwrap();
    assert!(
        sources
            .iter()
            .any(|(path, _)| path.ends_with("tests/leak_tests.rs")),
        "production #[path] target was omitted: {sources:?}"
    );
}

#[test]
fn excludes_only_module_edges_proven_exactly_test_only() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("lib.rs"),
        "#[cfg(test)] #[path = \"leak.rs\"] mod leak;",
    )
    .unwrap();
    std::fs::write(
        directory.path().join("leak.rs"),
        "compile_error!(\"test only\");",
    )
    .unwrap();
    let sources = surface_sources::load(directory.path()).unwrap();
    assert_eq!(sources.len(), 1, "test-only module became production input");
    assert!(sources[0].0.ends_with("lib.rs"));
}

#[test]
fn rejects_production_possible_cfg_attr_on_guarded_projection() {
    for condition in ["not(test)", "any(test, feature = \"alternate\")"] {
        let mut sources = production_sources();
        let projection = sources
            .iter_mut()
            .find(|(path, _)| path.ends_with("binding/candidate_binding.rs"))
            .unwrap();
        projection.1 = projection.1.replacen(
            "#[derive(Eq, PartialEq)]",
            &format!(
                "#[cfg_attr({condition}, derive(serde::Serialize))]\n#[derive(Eq, PartialEq)]"
            ),
            1,
        );
        let violations = surface_audit::audit(&sources);
        assert!(
            violations
                .iter()
                .any(|value| value.contains("guarded cfg_attr")),
            "cfg_attr escaped guard: {violations:?}"
        );
    }
}
