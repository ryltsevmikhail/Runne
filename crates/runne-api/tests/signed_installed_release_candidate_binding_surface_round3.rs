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

fn assert_ingress_rejected(source: &str) {
    let mut sources = production_sources();
    sources.push(("binding/wrapped_ingress.rs".into(), source.into()));
    let violations = surface_audit::audit(&sources);
    assert!(
        violations
            .iter()
            .any(|value| value.contains("exact-release ingress")),
        "wrapped exact ingress escaped: {violations:?}"
    );
}

#[test]
fn full_signature_traversal_rejects_wrapped_exact_release_types() {
    for source in [
        r#"
        pub(super) fn leak(
            source: impl std::borrow::Borrow<crate::VerifiedSignedInstalledReleaseV2>,
        ) -> Option<String> { unimplemented!() }
        "#,
        r#"
        pub(super) fn leak(
            source: &dyn std::borrow::Borrow<crate::VerifiedSignedInstalledReleaseV2>,
        ) -> Option<String> { unimplemented!() }
        "#,
        r#"
        pub(super) fn leak<T: std::borrow::Borrow<crate::VerifiedSignedInstalledReleaseV2>>(
            source: T,
        ) -> Option<String> { unimplemented!() }
        "#,
        r#"
        pub struct Helper;
        impl Helper {
            pub(crate) fn leak<T>(&self, source: T) -> String
            where T: std::borrow::Borrow<crate::VerifiedSignedInstalledReleaseV2>
            { unimplemented!() }
        }
        "#,
        r#"
        pub(super) fn leak(
            source: impl Iterator<Item = crate::VerifiedSignedInstalledReleaseV2>,
        ) -> Option<String> { unimplemented!() }
        "#,
    ] {
        assert_ingress_rejected(source);
    }
}

fn assert_graph_reaches_guard(lib: &str, files: &[(&str, &str)], expected: &str) {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("lib.rs"), lib).unwrap();
    for (path, source) in files {
        let path = directory.path().join(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, source).unwrap();
    }
    let sources = surface_sources::load(directory.path()).unwrap();
    assert!(
        sources.iter().any(|(path, _)| path.ends_with(expected)),
        "compiled source was omitted: {sources:?}"
    );
    let violations = surface_audit::audit(&sources);
    assert!(
        violations
            .iter()
            .any(|value| value.contains("exact-release method in")),
        "compiled source did not reach audit: {sources:?}; {violations:?}"
    );
}

const LEAK: &str =
    "impl crate::VerifiedSignedInstalledReleaseV2 { pub fn raw(&self) -> &str { \"x\" } }";

#[test]
fn tests_named_wrapped_and_qualified_includes_reach_audit() {
    assert_graph_reaches_guard(
        concat!(
            "macro_rules! load { ($path:literal) => { include!($path); } }\n",
            "load!(\"wrapped_tests.rs\");"
        ),
        &[("wrapped_tests.rs", LEAK)],
        "wrapped_tests.rs",
    );
    assert_graph_reaches_guard(
        "std::include!(\"qualified_tests.rs\");",
        &[("qualified_tests.rs", LEAK)],
        "qualified_tests.rs",
    );
    assert_graph_reaches_guard("", &[("orphan.inc", LEAK)], "orphan.inc");
}

#[test]
fn production_cfg_attr_path_edge_reaches_audit() {
    assert_graph_reaches_guard(
        "#[cfg_attr(not(test), path = \"leak_tests.rs\")] mod leak;",
        &[("leak.rs", "struct Benign;"), ("leak_tests.rs", LEAK)],
        "leak_tests.rs",
    );
}
