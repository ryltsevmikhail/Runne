use super::source_tree_audit::source_tree_violations;

#[test]
fn production_cli_has_no_local_macro_rules_definitions() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let violations = source_tree_violations(&root);
    assert!(
        violations
            .iter()
            .all(|violation| !violation.contains("macro_rules definition")),
        "production macro_rules definition found: {violations:#?}"
    );
}

#[test]
fn macro_emitted_source_references_are_rejected() {
    let cases = [
        (
            "nested include macro",
            "macro_rules! hidden { () => { include!(\"../outside.inc\") } } hidden!();",
        ),
        (
            "nested include_str macro",
            "macro_rules! hidden { () => { include_str!(\"../outside.txt\") } } hidden!();",
        ),
        (
            "nested include_bytes macro",
            "macro_rules! hidden { () => { include_bytes!(\"../outside.bin\") } } hidden!();",
        ),
        (
            "nested include macro",
            "macro_rules! hidden { ($name:ident) => { $name!(\"../outside.inc\") } } hidden!(include);",
        ),
        (
            "macro-emitted path attribute",
            "macro_rules! hidden { () => { #[path = \"../outside.rs\"] mod escaped; } } hidden!();",
        ),
        (
            "macro_rules definition",
            "macro_rules! hidden { ($name:ident) => { #[$name = \"../outside.rs\"] mod escaped; } } hidden!(path);",
        ),
    ];
    for (expected, source) in cases {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("main.rs"), source).unwrap();
        let violations = source_tree_violations(directory.path());
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains(expected)),
            "{expected} escaped macro token scan: {violations:#?}"
        );
    }
}

#[test]
fn ordinary_path_identifiers_in_macro_tokens_are_not_source_substitution() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("main.rs"),
        "macro_rules! passthrough { ($path:expr) => { $path }; }",
    )
    .unwrap();
    let violations = source_tree_violations(directory.path());
    assert!(
        violations.iter().all(
            |violation| !violation.contains("macro-emitted path attribute")
                && !violation.contains("nested include")
        ),
        "ordinary path identifier was rejected: {violations:#?}"
    );
}
