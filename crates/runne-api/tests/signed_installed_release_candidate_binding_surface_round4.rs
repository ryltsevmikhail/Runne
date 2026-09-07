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

fn audit_extra(source: &str) -> Vec<String> {
    let mut sources =
        surface_sources::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src")).unwrap();
    sources.push(("binding/round4.rs".into(), source.into()));
    surface_audit::audit(&sources)
}

fn assert_rejected(source: &str, category: &str) {
    let violations = audit_extra(source);
    assert!(
        violations.iter().any(|value| value.contains(category)),
        "{category} escaped: {source}\n{violations:?}"
    );
}

#[test]
fn trait_object_alias_chains_reach_ingress_policy() {
    for rhs in [
        "dyn std::borrow::Borrow<crate::VerifiedSignedInstalledReleaseV2>",
        "dyn Iterator<Item = crate::VerifiedSignedInstalledReleaseV2>",
        "dyn Iterator<Item: std::borrow::Borrow<crate::VerifiedSignedInstalledReleaseV2>>",
        "dyn Fn() -> crate::VerifiedSignedInstalledReleaseV2",
    ] {
        assert_rejected(
            &format!(
                "type Last = Middle; use First as Middle; type First = {rhs};
                 pub(super) fn leak(source: &Last) -> Option<String> {{ unimplemented!() }}"
            ),
            "exact-release ingress",
        );
    }
}

#[test]
fn projection_trait_object_alias_is_rejected() {
    assert_rejected(
        "type Alias = dyn std::borrow::Borrow<crate::VerifiedCandidateBindingV3>;",
        "projection alias",
    );
}

#[test]
fn alias_generic_defaults_cannot_hide_guarded_types() {
    assert_rejected(
        "type Alias<T = crate::VerifiedSignedInstalledReleaseV2> = T;
         pub(super) fn leak(source: &Alias) -> String { unimplemented!() }",
        "exact-release ingress",
    );
    assert_rejected(
        "type Alias<T = crate::VerifiedCandidateBindingV3> = T;",
        "projection alias",
    );
}

const TYPE_MACRO: &str =
    "macro_rules! exact_type { () => { crate::VerifiedSignedInstalledReleaseV2 }; }";

#[test]
fn unexpanded_type_macros_in_free_signatures_fail_closed() {
    for function in [
        "pub(super) fn leak(source: exact_type!()) -> String { unimplemented!() }",
        "fn leak(source: &Option<exact_type!()>) -> String { unimplemented!() }",
        "pub fn leak() -> exact_type!() { unimplemented!() }",
    ] {
        assert_rejected(&format!("{TYPE_MACRO} {function}"), "exact-release ingress");
    }
}

#[test]
fn unexpanded_type_macro_in_unrelated_method_fails_closed() {
    assert_rejected(
        &format!(
            "{TYPE_MACRO} struct Helper; impl Helper {{
             pub(crate) fn leak(source: &exact_type!()) -> String {{ unimplemented!() }} }}"
        ),
        "exact-release ingress",
    );
}

#[test]
fn unexpanded_alias_types_fail_closed_even_without_a_visible_user() {
    for alias in [
        "type Alias = exact_type!();",
        "type Alias = Option<exact_type!()>;",
        "type Alias = dyn Iterator<Item = exact_type!()>;",
        "type Alias<T = exact_type!()> = T;",
    ] {
        assert_rejected(&format!("{TYPE_MACRO} {alias}"), "projection alias");
    }
}

#[test]
fn only_proven_test_only_type_macros_are_excluded() {
    let fixture = format!("{TYPE_MACRO} type Alias = exact_type!();");
    assert!(audit_extra(&format!("#[cfg(test)] mod fixtures {{ {fixture} }}")).is_empty());
    for condition in ["not(test)", "any(test, unix)"] {
        assert_rejected(
            &format!("#[cfg({condition})] mod fixtures {{ {fixture} }}"),
            "projection alias",
        );
    }
}

fn load_fixture(lib: &str, files: &[(&str, &str)]) -> Result<Vec<(String, String)>, String> {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("lib.rs"), lib).unwrap();
    for (name, contents) in files {
        std::fs::write(directory.path().join(name), contents).unwrap();
    }
    surface_sources::load(directory.path())
}

const LEAK: &str =
    "impl crate::VerifiedSignedInstalledReleaseV2 { pub fn raw(&self) -> &str { \"x\" } }";
const WRAPPER: &str = "macro_rules! load { ($path:literal) => { include!($path); } }";

fn assert_loaded_and_audited(lib: &str, name: &str, extra: &[(&str, &str)]) {
    let mut files = extra.to_vec();
    files.push((name, LEAK));
    let sources = load_fixture(lib, &files).unwrap();
    assert!(
        sources.iter().any(|(path, _)| path.ends_with(name)),
        "compiled source omitted: {lib}; {sources:?}"
    );
    let violations = surface_audit::audit(&sources);
    assert!(
        violations
            .iter()
            .any(|value| value.contains("exact-release method in"))
    );
}

#[test]
fn wrappers_follow_nonstandard_extensionless_raw_and_escaped_paths() {
    for (literal, name) in [
        (r#""leak.fragment""#, "leak.fragment"),
        (r#""leak""#, "leak"),
        (r##"r#"leak.raw"#"##, "leak.raw"),
        (r#""leak\x2efragment""#, "leak.fragment"),
    ] {
        assert_loaded_and_audited(&format!("{WRAPPER} load!({literal});"), name, &[]);
    }
}

#[test]
fn qualified_and_unknown_literal_wrappers_follow_existing_files_without_suffix_filter() {
    for invocation in ["std::include!", "other::load!", "load_alias!"] {
        assert_loaded_and_audited(
            &format!("{invocation}(\"leak.fragment\");"),
            "leak.fragment",
            &[],
        );
    }
}

#[test]
fn unresolved_include_definitions_and_wrapper_invocations_fail_closed() {
    for source in [
        "macro_rules! load { ($path:literal) => { include!(concat!($path, \".fragment\")); } }",
        "macro_rules! load { ($path:literal) => { include!(\"benign.rs\"); include!($path); } }",
        "macro_rules! load { ($path:literal) => { include!($path); }; () => { include!(env!(\"SOURCE\")); } }",
        "macro_rules! load { () => { include!(env!(\"SOURCE\")); } }",
    ] {
        assert!(
            load_fixture(source, &[("benign.rs", "struct Benign;")]).is_err(),
            "unresolved definition escaped: {source}"
        );
    }
    for invocation in [
        "load!(\"missing.fragment\");",
        "load!(concat!(\"benign.rs\", \".fragment\"));",
        "load!(env!(\"SOURCE\"));",
        "std::include!(concat!(\"benign.rs\", \".fragment\"));",
    ] {
        let source = format!("{WRAPPER} {invocation}");
        assert!(
            load_fixture(&source, &[("benign.rs", "struct Benign;")]).is_err(),
            "unresolved invocation escaped: {source}"
        );
    }
}

#[test]
fn nested_production_cfg_attr_paths_reach_audit_with_benign_defaults() {
    for attributes in [
        r#"#[cfg_attr(not(test), cfg_attr(unix, path = "leak_tests.rs"))]"#,
        r#"#[cfg_attr(any(test, unix), cfg_attr(unix, cfg_attr(not(test), path = "leak_tests.rs")))]"#,
        r#"#[cfg_attr(not(test), cfg_attr(unix, path = "leak_tests.rs"))] #[path = "benign.rs"]"#,
    ] {
        assert_loaded_and_audited(
            &format!("{attributes} mod leak;"),
            "leak_tests.rs",
            &[
                ("leak.rs", "struct Benign;"),
                ("benign.rs", "struct Benign;"),
            ],
        );
    }
}

#[test]
fn nested_paths_skip_only_proven_test_conditions_and_reject_nonliteral_paths() {
    for attributes in [
        r#"#[cfg_attr(test, cfg_attr(unix, path = "missing"))]"#,
        r#"#[cfg_attr(unix, cfg_attr(all(test, unix), path = "missing"))]"#,
    ] {
        let sources = load_fixture(
            &format!("{attributes} mod leak;"),
            &[("leak.rs", "struct Benign;")],
        )
        .unwrap();
        assert_eq!(sources.len(), 2);
    }
    assert!(
        load_fixture(
            r#"#[cfg_attr(not(test), cfg_attr(unix, path = concat!("leak", ".rs")))] mod leak;"#,
            &[("leak.rs", "struct Benign;")],
        )
        .is_err()
    );
}
