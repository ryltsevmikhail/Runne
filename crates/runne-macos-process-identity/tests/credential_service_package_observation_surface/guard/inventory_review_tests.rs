use super::inventory_tests::{CALLER, cargo_check, workspace};

const CALLER_EXPR: &str = "{ let _ = Pending::capture_current(); 0 }";

use super::semantic_graph_acceptance_tests::calls;

#[path = "inventory_review_tests/dependency_aliases.rs"]
mod dependency_aliases;

#[test]
fn inventory_follows_include_nested_in_json_expression_macro() {
    let workspace = workspace();
    workspace.write(
        "crates/example/Cargo.toml",
        r#"
            [package]
            name = "example"
            version = "0.1.0"
            edition = "2024"
            [lib]
            path = "src/lib.rs"
            [dependencies]
            runne-macos-process-identity = { path = "../../identity" }
            serde_json = "1.0.151"
        "#,
    );
    workspace.write(
        "crates/example/src/lib.rs",
        "use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending; pub fn production() { let _ = serde_json::json!(include!(\"payload.inc\")); }",
    );
    workspace.write("crates/example/src/payload.inc", CALLER_EXPR);

    cargo_check(&workspace);
    let facade = workspace.path().join("crates/example/src/lib.rs");
    let snapshot = super::collect_workspace_production_snapshot(workspace.path(), &facade);
    assert!(
        snapshot.graph.nodes.iter().any(|node| {
            node.canonical_path.ends_with("payload.inc") && node.bytes == CALLER_EXPR
        })
    );
    let index = super::semantic_index::SemanticIndex::build(&snapshot).unwrap();
    assert!(matches!(
        super::analyzer::analyze(&index),
        super::analyzer::GuardVerdict::Inconclusive(_)
    ));
}

#[test]
fn opaque_external_item_macro_is_an_inconclusive_source_edge() {
    let workspace = workspace();
    workspace.write(
        "Cargo.toml",
        "[workspace]\nmembers = [\"crates/example\"]\nexclude = [\"helper\"]\nresolver = \"2\"",
    );
    workspace.write(
        "helper/Cargo.toml",
        "[package]\nname = \"helper\"\nversion = \"0.1.0\"\nedition = \"2021\"",
    );
    workspace.write(
        "helper/src/lib.rs",
        "#[macro_export] macro_rules! extern_protocol { () => { pub fn generated() {} } }",
    );
    workspace.write(
        "crates/example/Cargo.toml",
        "[package]\nname = \"example\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[dependencies]\nhelper = { path = \"../../helper\" }",
    );
    workspace.write(
        "crates/example/src/lib.rs",
        "use helper::extern_protocol; extern_protocol!();",
    );

    cargo_check(&workspace);
    let verdict = super::semantic_graph_acceptance_tests::verdict(&workspace);
    assert!(
        matches!(
            verdict,
            super::analyzer::GuardVerdict::Inconclusive(ref sites)
                if sites.iter().any(|site| {
                    site.source.is_some()
                        && site.reason == super::provenance::UnresolvedReason::OpaqueSourceMacro
                        && site.detail == "opaque production source macro expansion: extern_protocol"
                })
        ),
        "opaque production item macro must block exact-zero inventory: {verdict:?}"
    );
}

#[test]
fn inventory_resolves_local_macro_reexport_named_json() {
    let workspace = workspace();
    workspace.write(
        "crates/example/src/lib.rs",
        "mod macros { macro_rules! emit_mod { () => { mod hidden; } } pub(crate) use emit_mod as json; } use macros::json; json!();",
    );
    workspace.write("crates/example/src/hidden.rs", CALLER);

    cargo_check(&workspace);
    assert_eq!(calls(&workspace), 1);
}

#[test]
fn inventory_resolves_local_macro_reexport_with_ordinary_alias() {
    let workspace = workspace();
    workspace.write(
        "crates/example/src/lib.rs",
        "mod macros { macro_rules! emit_mod { () => { mod hidden; } } pub(crate) use emit_mod as alias; } use macros::alias; alias!();",
    );
    workspace.write("crates/example/src/hidden.rs", CALLER);

    cargo_check(&workspace);
    assert_eq!(calls(&workspace), 1);
}

#[test]
fn inventory_never_selects_late_same_file_macro_for_earlier_nested_call() {
    let workspace = workspace();
    workspace.write(
        "crates/example/src/lib.rs",
        "#[macro_use] mod imported; load!(); macro_rules! load { () => { include!(\"decoy.inc\"); } }",
    );
    workspace.write(
        "crates/example/src/imported.rs",
        "macro_rules! load { () => { include!(\"actual.inc\"); } }",
    );
    workspace.write("crates/example/src/actual.inc", CALLER);
    workspace.write("crates/example/src/decoy.inc", "pub fn decoy() {}");

    cargo_check(&workspace);
    assert_eq!(calls(&workspace), 1);
}

#[test]
fn inventory_resolves_qualified_macro_path_without_using_root_name() {
    let workspace = workspace();
    workspace.write(
        "crates/example/src/lib.rs",
        r#"
            macro_rules! load { () => {}; }
            mod left {
                macro_rules! load { () => { include!("payload.inc"); } }
                pub(crate) use load;
            }
            left::load!();
        "#,
    );
    workspace.write("crates/example/src/payload.inc", CALLER);

    cargo_check(&workspace);
    assert_eq!(calls(&workspace), 1);
}

#[test]
fn inventory_follows_consumer_relative_include_from_exported_macro() {
    let workspace = workspace();
    workspace.write(
        "helper/Cargo.toml",
        "[package]\nname = \"helper\"\nversion = \"0.1.0\"\nedition = \"2024\"",
    );
    workspace.write(
        "helper/src/lib.rs",
        "#[macro_export] macro_rules! load { () => { include!(\"payload.inc\"); } }",
    );
    workspace.write(
        "crates/example/Cargo.toml",
        r#"
            [package]
            name = "example"
            version = "0.1.0"
            edition = "2024"
            [lib]
            path = "src/lib.rs"
            [dependencies]
            helper = { path = "../../helper" }
            runne-macos-process-identity = { path = "../../identity" }
        "#,
    );
    workspace.write("crates/example/src/lib.rs", "use helper::load; load!();");
    workspace.write("crates/example/src/payload.inc", CALLER);

    cargo_check(&workspace);
    assert_eq!(calls(&workspace), 1);
}

#[test]
fn inventory_preserves_path_on_macro_generated_module() {
    let workspace = workspace();
    workspace.write(
        "crates/example/src/lib.rs",
        "macro_rules! emit { () => { #[path = \"actual.rs\"] mod hidden; } } emit!();",
    );
    workspace.write("crates/example/src/actual.rs", CALLER);
    workspace.write("crates/example/src/hidden.rs", "pub fn decoy() {}");

    cargo_check(&workspace);
    assert_eq!(calls(&workspace), 1);
}

#[test]
fn inventory_does_not_follow_unselected_source_macro_arm() {
    let workspace = workspace();
    workspace.write(
        "crates/example/src/lib.rs",
        "macro_rules! choose { (safe) => {}; (danger) => { include!(\"payload.inc\"); } } choose!(safe);",
    );
    workspace.write("crates/example/src/payload.inc", CALLER);

    cargo_check(&workspace);
    assert_eq!(calls(&workspace), 0);
}

#[test]
fn inventory_follows_selected_source_macro_arm() {
    let workspace = workspace();
    workspace.write(
        "crates/example/src/lib.rs",
        "macro_rules! choose { (safe) => {}; (danger) => { include!(\"payload.inc\"); } } choose!(danger);",
    );
    workspace.write("crates/example/src/payload.inc", CALLER);

    cargo_check(&workspace);
    assert_eq!(calls(&workspace), 1);
}

#[test]
fn inventory_keeps_include_alias_in_its_inline_module_scope() {
    let workspace = workspace();
    workspace.write(
        "crates/example/src/lib.rs",
        "mod left { use std::include as load; } mod right { macro_rules! load { ($ignored:literal) => { include!(\"actual.inc\"); } } load!(\"decoy.inc\"); }",
    );
    workspace.write("crates/example/src/actual.inc", CALLER);
    workspace.write("crates/example/src/decoy.inc", "pub fn decoy() {}");

    cargo_check(&workspace);
    assert_eq!(calls(&workspace), 1);
}

#[test]
fn inventory_ignores_include_in_test_only_expression() {
    let workspace = workspace();
    workspace.write(
        "crates/example/src/lib.rs",
        "use runne_macos_process_identity::MacOsPendingCredentialServicePackageObservationV1 as Pending; pub fn production() { #[cfg(test)] { include!(\"test.inc\"); } }",
    );
    workspace.write("crates/example/src/test.inc", CALLER_EXPR);

    cargo_check(&workspace);
    assert_eq!(calls(&workspace), 0);
}

#[test]
fn inventory_ignores_test_only_macro_generated_module() {
    let workspace = workspace();
    workspace.write(
        "crates/example/src/lib.rs",
        "macro_rules! emit { () => { #[cfg(test)] mod hidden; } } emit!();",
    );
    workspace.write("crates/example/src/hidden.rs", CALLER);

    cargo_check(&workspace);
    assert_eq!(calls(&workspace), 0);
}
