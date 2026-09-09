use super::super::super::{find_production_callers, fixture};

#[test]
fn local_module_reexport_cannot_spoof_a_compiler_builtin() {
    let source = fixture(
        "src/local_builtin_reexport.rs",
        "mod facade { pub use external_proc::matches; } use facade::matches; fn release() { matches!(); }",
        false,
    );

    assert_eq!(find_production_callers(&[source]).len(), 1);
}

#[test]
fn raw_identifier_import_cannot_spoof_a_compiler_builtin() {
    let source = fixture(
        "src/raw_builtin_import.rs",
        "use external_proc::r#matches; fn release() { r#matches!(); }",
        false,
    );

    assert_eq!(find_production_callers(&[source]).len(), 1);
}

#[test]
fn cross_file_local_glob_cannot_export_a_trusted_root() {
    let mut caller = fixture(
        "src/lib.rs",
        "mod facade; use facade::*; fn release() { serde_json::json!(); }",
        false,
    );
    caller
        .trusted_external_roots
        .insert("serde_json".to_owned());
    let reexport = fixture(
        "src/facade.rs",
        "pub use external_proc as serde_json;",
        false,
    );

    assert_eq!(find_production_callers(&[caller, reexport]).len(), 1);
}

#[test]
fn rooted_cross_file_globs_cannot_export_a_trusted_root() {
    for source in [
        "mod facade; use crate::facade::*; fn release() { serde_json::json!(); }",
        "mod facade; use self::facade::*; fn release() { serde_json::json!(); }",
        "mod facade; mod child { use super::facade::*; fn release() { serde_json::json!(); } }",
    ] {
        let mut caller = fixture("src/lib.rs", source, false);
        caller
            .trusted_external_roots
            .insert("serde_json".to_owned());
        let reexport = fixture(
            "src/facade.rs",
            "pub use external_proc as serde_json;",
            false,
        );

        assert_eq!(find_production_callers(&[caller, reexport]).len(), 1);
    }
}

#[test]
fn nonconventional_module_paths_cannot_hide_a_globbed_trusted_root() {
    for (declaration, path) in [
        ("mod facade;", "src/facade/mod.rs"),
        ("#[path = \"renamed.rs\"] mod facade;", "src/renamed.rs"),
    ] {
        let mut caller = fixture(
            "src/lib.rs",
            &format!(
                "{declaration} use crate::facade::*; fn release<T: CredentialServiceQualificationPort>(port: &T) {{ serde_json::json!(port); }}"
            ),
            false,
        );
        caller
            .trusted_external_roots
            .insert("serde_json".to_owned());
        let reexport = fixture(
            path,
            "pub mod serde_json { pub use external_proc::json; }",
            false,
        );

        assert_eq!(find_production_callers(&[caller, reexport]).len(), 1);
    }
}

#[test]
fn block_local_imports_cannot_spoof_a_trusted_macro_path() {
    let direct_alias = "fn release() { use external_proc as serde_json; serde_json::json!(); }";
    let local_glob = "mod facade { pub use external_proc as serde_json; } fn release() { use crate::facade::*; serde_json::json!(); }";
    for source in [direct_alias, local_glob] {
        let mut unit = fixture("src/block_import.rs", source, false);
        unit.trusted_external_roots.insert("serde_json".to_owned());
        assert_eq!(find_production_callers(&[unit]).len(), 1);
    }
}
