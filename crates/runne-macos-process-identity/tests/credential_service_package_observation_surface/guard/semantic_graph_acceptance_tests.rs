use super::inventory_tests::{TemporaryWorkspace, cargo_check, workspace};

pub(super) fn calls(workspace: &TemporaryWorkspace) -> usize {
    match verdict(workspace) {
        super::analyzer::GuardVerdict::Clean => 0,
        super::analyzer::GuardVerdict::Calls(sites) => sites.len(),
        verdict @ super::analyzer::GuardVerdict::Inconclusive(_) => {
            panic!("fixture graph must resolve conclusively: {verdict:?}")
        }
    }
}

pub(super) fn verdict(workspace: &TemporaryWorkspace) -> super::analyzer::GuardVerdict {
    let facade = workspace.path().join("crates/example/src/lib.rs");
    let snapshot = super::collect_workspace_production_snapshot(workspace.path(), &facade);
    let index = super::semantic_index::SemanticIndex::build(&snapshot)
        .expect("complete fixture source graph");
    super::analyzer::analyze(&index)
}

fn shared_include_workspace(reverse_modules: bool) -> TemporaryWorkspace {
    let workspace = workspace();
    let target = r#"
        mod production {
            use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Subject;
            include!("shared.inc");
        }
    "#;
    let unrelated = r#"
        mod unrelated {
            struct Subject;
            impl Subject { fn capture_current() {} }
            include!("shared.inc");
        }
    "#;
    let source = if reverse_modules {
        format!("{unrelated}\n{target}")
    } else {
        format!("{target}\n{unrelated}")
    };
    workspace.write("crates/example/src/lib.rs", &source);
    workspace.write(
        "crates/example/src/shared.inc",
        "pub fn caller() { let _ = Subject::capture_current(); }",
    );
    workspace
}

#[test]
fn shared_include_keeps_lexical_owner_for_each_expansion_site() {
    for reverse_modules in [false, true] {
        let workspace = shared_include_workspace(reverse_modules);
        cargo_check(&workspace);
        assert_eq!(calls(&workspace), 1, "each include must retain its context");
    }
}

#[test]
fn cross_file_item_macro_keeps_the_definition_and_invocation_modules() {
    let workspace = workspace();
    workspace.write(
        "crates/example/src/lib.rs",
        "pub use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending; #[macro_use] mod macros; emit!();",
    );
    workspace.write(
        "crates/example/src/macros.rs",
        "macro_rules! emit { () => { fn production() { let _ = $crate::Pending::capture_current(); } } }",
    );
    cargo_check(&workspace);
    assert_eq!(calls(&workspace), 1);
}

#[test]
fn cross_crate_item_macro_resolves_dollar_crate_to_its_definition() {
    let workspace = workspace();
    workspace.write(
        "helper/Cargo.toml",
        "[package]\nname = \"helper\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nrunne-macos-process-identity = { path = \"../identity\" }",
    );
    workspace.write(
        "helper/src/lib.rs",
        "pub use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending; #[macro_export] macro_rules! emit { () => { pub fn production() { let _ = $crate::Pending::capture_current(); } } }",
    );
    workspace.write(
        "crates/example/Cargo.toml",
        "[package]\nname = \"example\"\nversion = \"0.1.0\"\nedition = \"2021\"\nbuild = \"custom/build.rs\"\n[dependencies]\nhelper = { path = \"../../helper\" }",
    );
    workspace.write("crates/example/src/lib.rs", "use helper::emit; emit!();");
    cargo_check(&workspace);
    assert_eq!(calls(&workspace), 1);
}

#[test]
fn statement_include_never_loses_parent_local_callable() {
    let workspace = workspace();
    workspace.write(
        "crates/example/src/lib.rs",
        "use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending; pub fn production() { let capture = Pending::capture_current; include!(\"body.inc\"); }",
    );
    workspace.write("crates/example/src/body.inc", "{ let _ = capture(); }");
    cargo_check(&workspace);
    assert!(
        !matches!(verdict(&workspace), super::analyzer::GuardVerdict::Clean),
        "unresolved include-site bindings must block the zero-caller gate"
    );
}

#[test]
fn non_literal_include_argument_resolves_to_structured_inconclusive() {
    let workspace = workspace();
    workspace.write(
        "crates/example/src/lib.rs",
        "use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending; include!(concat!(\"pay\", \"load.inc\"));",
    );
    workspace.write(
        "crates/example/src/payload.inc",
        "pub fn caller() { let _ = Pending::capture_current(); }",
    );
    cargo_check(&workspace);
    assert!(
        matches!(
            verdict(&workspace),
            super::analyzer::GuardVerdict::Inconclusive(_)
        ),
        "non-literal include argument must fail closed without panicking"
    );
}

#[test]
fn dynamic_macro_module_edge_resolves_to_structured_inconclusive() {
    let workspace = workspace();
    workspace.write(
        "crates/example/src/lib.rs",
        "use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending; macro_rules! emit { ($name:ident) => { mod $name; } } emit!(hidden);",
    );
    workspace.write(
        "crates/example/src/hidden.rs",
        "use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending; pub fn caller() { let _ = Pending::capture_current(); }",
    );
    cargo_check(&workspace);
    assert!(
        matches!(
            verdict(&workspace),
            super::analyzer::GuardVerdict::Inconclusive(_)
        ),
        "macro-generated dynamic module edge must fail closed without panicking"
    );
}
