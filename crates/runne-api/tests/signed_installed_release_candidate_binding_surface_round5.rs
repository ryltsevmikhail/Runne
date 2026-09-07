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

const FAMILIES: [&str; 2] = [
    "crate::VerifiedSignedInstalledReleaseV2",
    "crate::VerifiedCandidateBindingV3",
];
const WRAPPER: &str = "macro_rules! load { ($path:literal) => { include!($path); } }";
const MEMBER: &str = "pub(super) fn leak(source: &crate::VerifiedSignedInstalledReleaseV2)
    -> Option<String> { unimplemented!() }";

fn audit_extra(source: &str) -> Vec<String> {
    let mut sources =
        surface_sources::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src")).unwrap();
    sources.push(("binding/round5.rs".into(), source.into()));
    surface_audit::audit(&sources)
}

fn assert_rejected(source: &str, category: &str) {
    let violations = audit_extra(source);
    assert!(
        violations.iter().any(|value| value.contains(category)),
        "{category} escaped: {source}\n{violations:?}"
    );
    assert!(
        !violations
            .iter()
            .any(|value| value.contains("parse failure"))
    );
}

fn assignment(family: &str) -> String {
    format!(
        "pub(super) trait Slot {{ type Value; }} pub(super) struct ExactSlot;
         impl Slot for ExactSlot {{ type Value = {family}; }}"
    )
}

#[test]
fn associated_assignments_are_rejected_even_without_projection_users() {
    for family in FAMILIES {
        assert_rejected(&assignment(family), "guarded associated type");
        assert_rejected(
            &format!(
                "{} type First = Last; use {family} as Last;",
                assignment("First")
            ),
            "guarded associated type",
        );
    }
}

#[test]
fn associated_defaults_are_rejected_even_through_aliases() {
    for family in FAMILIES {
        assert_rejected(
            &format!("trait Slot {{ type Value = Alias; }} type Alias = {family};"),
            "guarded associated type",
        );
    }
}

#[test]
fn associated_projection_alias_chains_reach_family_policy() {
    for (family, category) in FAMILIES
        .into_iter()
        .zip(["exact-release ingress", "projection alias"])
    {
        assert_rejected(
            &format!(
                "{} type Hidden = <ExactSlot as Slot>::Value;
                 use Hidden as Middle; type Last = Middle;
                 pub(super) fn leak(source: &Last) -> String {{ unimplemented!() }}",
                assignment(family)
            ),
            category,
        );
    }
}

#[test]
fn direct_associated_projections_reach_free_and_method_ingress() {
    for family in FAMILIES {
        for signature in [
            "fn leak(source: &<ExactSlot as Slot>::Value) -> String",
            "fn leak() -> <ExactSlot as Slot>::Value",
            "fn leak<T: Slot>(source: &T::Value) -> String",
        ] {
            let definitions = assignment(family);
            let category = if family == FAMILIES[0] {
                "exact-release ingress"
            } else {
                "projection signature"
            };
            assert_rejected(
                &format!("{definitions} pub(super) {signature} {{ unimplemented!() }}"),
                category,
            );
            assert_rejected(
                &format!(
                    "{definitions} struct Helper; impl Helper {{
                     pub(super) {signature} {{ unimplemented!() }} }}"
                ),
                category,
            );
        }
    }
}

#[test]
fn unresolved_associated_projections_fail_closed_in_aliases_and_signatures() {
    for projection in ["<Foreign as external::Slot>::Value", "<Foreign>::Value"] {
        assert_rejected(
            &format!("pub type Hidden = {projection};"),
            "projection alias",
        );
        let method = format!("fn leak(source: &Option<{projection}>) -> String");
        assert_rejected(
            &format!("pub(super) {method} {{ unimplemented!() }}"),
            "exact-release ingress",
        );
        assert_rejected(
            &format!("pub trait Facade {{ {method}; }}"),
            "guarded associated signature",
        );
    }
}

#[test]
fn associated_types_skip_only_proven_test_cfg() {
    for family in FAMILIES {
        for source in [
            format!("#[cfg(test)] mod fixture {{ {} }}", assignment(family)),
            format!("#[cfg(test)] impl Slot for ExactSlot {{ type Value = {family}; }}"),
            format!("#[cfg(test)] trait Slot {{ type Value = {family}; }}"),
            format!("impl Slot for ExactSlot {{ #[cfg(test)] type Value = {family}; }}"),
            format!("trait Slot {{ #[cfg(test)] type Value = {family}; }}"),
        ] {
            assert!(
                audit_extra(&source).is_empty(),
                "test-only source was audited: {source}"
            );
            for condition in ["not(test)", "any(test, unix)"] {
                assert_rejected(
                    &source.replace("cfg(test)", &format!("cfg({condition})")),
                    "guarded associated type",
                );
            }
        }
    }
}

fn load_fixture(source: &str, files: &[(&str, &str)]) -> Result<Vec<(String, String)>, String> {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("lib.rs"), source).unwrap();
    for (name, contents) in files {
        std::fs::write(directory.path().join(name), contents).unwrap();
    }
    surface_sources::load(directory.path())
}

fn assert_associated_macro_rejected(source: &str, files: &[(&str, &str)]) {
    let result = load_fixture(source, files);
    let error = result.expect_err("associated-item source silently omitted");
    assert!(
        error.contains("associated-item macro"),
        "wrong rejection: {error}"
    );
    assert!(error.contains("lib.rs"), "missing source context: {error}");
}

#[test]
fn unrelated_impl_direct_nonstandard_includes_fail_closed() {
    for (literal, name) in [
        (r#""leak.fragment""#, "leak.fragment"),
        (r#""leak""#, "leak"),
        (r##"r#"leak.raw"#"##, "leak.raw"),
        (r#""leak\x2efragment""#, "leak.fragment"),
    ] {
        for invocation in ["include!", "std::include!"] {
            assert_associated_macro_rejected(
                &format!("struct Helper; impl Helper {{ {invocation}({literal}); }}"),
                &[(name, MEMBER)],
            );
        }
    }
}

#[test]
fn unrelated_impl_supported_wrapper_nonstandard_includes_fail_closed() {
    for invocation in ["load!", "other::load!", "load_alias!"] {
        assert_associated_macro_rejected(
            &format!("{WRAPPER} struct Helper; impl Helper {{ {invocation}(\"leak.fragment\"); }}"),
            &[("leak.fragment", MEMBER)],
        );
    }
}

#[test]
fn associated_macros_in_nested_items_and_traits_fail_closed() {
    for source in [
        "mod nested { struct Helper; impl Helper { include!(\"leak.fragment\"); } }",
        "fn helper() { struct Helper; impl Helper { include!(\"leak.fragment\"); } }",
        "const VALUE: () = { struct Helper; impl Helper { include!(\"leak.fragment\"); } };",
        "struct Outer; impl Outer { fn helper() {
            struct Helper; impl Helper { include!(\"leak.fragment\"); } } }",
        "trait Helper { include!(\"leak.fragment\"); }",
    ] {
        assert_associated_macro_rejected(source, &[("leak.fragment", MEMBER)]);
    }
}

#[test]
fn computed_missing_and_opaque_associated_macros_fail_closed() {
    for invocation in [
        "include!(concat!(\"leak\", \".fragment\"));",
        "include!(\"missing.fragment\");",
        "load!(env!(\"SOURCE\"));",
        "external::load!();",
    ] {
        assert_associated_macro_rejected(
            &format!("{WRAPPER} struct Helper; impl Helper {{ {invocation} }}"),
            &[],
        );
    }
}

#[test]
fn associated_macros_skip_only_proven_test_cfg() {
    for source in [
        "#[cfg(test)] mod fixture { impl Helper { include!(\"missing.fragment\"); } }",
        "#[cfg(test)] impl Helper { include!(\"missing.fragment\"); }",
        "impl Helper { #[cfg(test)] include!(\"missing.fragment\"); }",
        "#[cfg(test)] trait Helper { include!(\"missing.fragment\"); }",
        "trait Helper { #[cfg(test)] include!(\"missing.fragment\"); }",
        "#[cfg(test)] fn fixture() { impl Helper { include!(\"missing.fragment\"); } }",
        "impl Outer { #[cfg(test)] fn fixture() {
            impl Helper { include!(\"missing.fragment\"); } } }",
    ] {
        assert!(
            load_fixture(source, &[]).is_ok(),
            "test-only source was loaded: {source}"
        );
        for condition in ["not(test)", "any(test, unix)"] {
            assert_associated_macro_rejected(
                &source.replace("cfg(test)", &format!("cfg({condition})")),
                &[],
            );
        }
    }
}

#[test]
fn benign_associated_types_and_frozen_production_surface_remain_accepted() {
    let source = "trait Slot { type Value = String; } struct Helper;
        impl Slot for Helper { type Value = String; }
        impl Helper { fn inspect<T: Slot>(source: &T::Value) {} }";
    assert!(audit_extra(source).is_empty());
    assert!(load_fixture(source, &[]).is_ok());
}
