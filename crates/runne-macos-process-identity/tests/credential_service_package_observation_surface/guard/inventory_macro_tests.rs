use super::inventory_tests::{CALLER, cargo_check, production_sources, workspace};
use super::semantic_graph_acceptance_tests::calls;

#[test]
fn inventory_follows_module_generated_by_reachable_macro() {
    let workspace = workspace();
    workspace.write(
        "crates/example/src/lib.rs",
        "macro_rules! emit_mod { () => { mod hidden; } } emit_mod!();",
    );
    workspace.write("crates/example/src/hidden.rs", CALLER);

    cargo_check(&workspace);
    assert_eq!(calls(&workspace), 1);
}

#[test]
fn inventory_follows_transitive_macro_wrapped_include() {
    let workspace = workspace();
    workspace.write(
        "crates/example/src/lib.rs",
        r#"
            macro_rules! inner { ($path:literal) => { include!($path); } }
            macro_rules! outer { ($path:literal) => { inner!($path); } }
            outer!("payload.inc");
        "#,
    );
    workspace.write("crates/example/src/payload.inc", CALLER);

    cargo_check(&workspace);
    assert_eq!(calls(&workspace), 1);
}

#[test]
fn inventory_resolves_imported_include_alias() {
    let workspace = workspace();
    workspace.write(
        "crates/example/src/lib.rs",
        "use std::include as load; load!(\"payload.inc\");",
    );
    workspace.write("crates/example/src/payload.inc", CALLER);

    cargo_check(&workspace);
    assert_eq!(calls(&workspace), 1);
}

#[test]
fn inventory_does_not_follow_include_in_unused_macro_definition() {
    let workspace = workspace();
    workspace.write(
        "crates/example/src/lib.rs",
        "macro_rules! unused { () => { include!(\"payload.inc\"); } }",
    );
    workspace.write("crates/example/src/payload.inc", CALLER);

    cargo_check(&workspace);
    assert_eq!(production_sources(&workspace).len(), 3);
    assert_eq!(calls(&workspace), 0);
}

#[test]
fn inventory_follows_source_tokens_forwarded_by_reachable_macro() {
    let workspace = workspace();
    workspace.write(
        "crates/example/src/lib.rs",
        "macro_rules! forward { ($($item:tt)*) => { $($item)* } } forward!(mod hidden;);",
    );
    workspace.write("crates/example/src/hidden.rs", CALLER);

    cargo_check(&workspace);
    assert_eq!(calls(&workspace), 1);
}

#[test]
fn inventory_never_mixes_same_named_macros_across_inline_scopes() {
    let workspace = workspace();
    workspace.write(
        "crates/example/src/lib.rs",
        r#"
            mod left {
                macro_rules! load { () => { include!("left.inc"); } }
                load!();
            }
            mod right {
                macro_rules! load { () => { include!("right.inc"); } }
            }
        "#,
    );
    workspace.write("crates/example/src/left.inc", CALLER);
    workspace.write("crates/example/src/right.inc", CALLER);

    cargo_check(&workspace);
    let result = std::panic::catch_unwind(|| calls(&workspace));
    if let Ok(count) = result {
        assert_eq!(count, 1);
    }
}

#[test]
fn inventory_resolves_or_fails_closed_on_dynamic_include_argument() {
    let workspace = workspace();
    workspace.write(
        "crates/example/src/lib.rs",
        r#"
            macro_rules! load { ($path:expr) => { include!($path); } }
            load!(concat!("payload", ".inc"));
        "#,
    );
    workspace.write("crates/example/src/payload.inc", CALLER);

    cargo_check(&workspace);
    let result = std::panic::catch_unwind(|| calls(&workspace));
    if let Ok(count) = result {
        assert_eq!(count, 1);
    }
}
