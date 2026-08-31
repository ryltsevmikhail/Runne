#![cfg(test)]

use std::path::Path;

mod source_tree;
use source_tree::{collect_source_tree_violations, daemon_source_violations};

#[test]
fn daemon_has_no_native_writer_capability() {
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let violations = daemon_source_violations(&source);
    assert!(
        violations.is_empty(),
        "daemon source retains native writer capability:\n{}",
        violations.join("\n")
    );
}

#[test]
fn runned_cannot_call_writer() {
    let manifest = include_str!("../Cargo.toml");
    assert!(
        !manifest.contains("provider-credential-broker-writer"),
        "runned must not enable the runne-secure-store writer feature"
    );
}

#[test]
fn unreferenced_nested_source_file_cannot_hide_writer_call() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir(directory.path().join("unlisted")).unwrap();
    std::fs::write(directory.path().join("lib.rs"), "").unwrap();
    std::fs::write(
        directory.path().join("unlisted/hidden.rs"),
        "fn bypass(native: &dyn Store, claim: Claim) { native.delete_version(claim); }\n",
    )
    .unwrap();

    let violations = collect_source_tree_violations(directory.path(), &[]);

    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("unlisted/hidden.rs")
                && violation.contains("delete_version")),
        "unreferenced nested source bypassed writer boundary scan: {violations:?}"
    );
}

#[test]
fn included_non_rust_extension_cannot_hide_writer_call() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("lib.rs"),
        "include!(\"hidden.inc\");\n",
    )
    .unwrap();
    std::fs::write(
        directory.path().join("hidden.inc"),
        "fn bypass(native: &dyn Store, claim: Claim) { native.create_version(claim); }\n",
    )
    .unwrap();

    let violations = collect_source_tree_violations(directory.path(), &[]);

    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("hidden.inc")
                && violation.contains("create_version")),
        "included non-.rs source bypassed writer boundary scan: {violations:?}"
    );
}

#[test]
fn parent_path_source_indirection_cannot_escape_scan_root() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("src");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(
        source.join("lib.rs"),
        "#[path = \"../writer.rs\"] mod writer;\n",
    )
    .unwrap();
    std::fs::write(directory.path().join("writer.rs"), "fn writer() {}\n").unwrap();

    let violations = collect_source_tree_violations(&source, &[]);

    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("source indirection escapes scan root")),
        "parent path escaped writer boundary scan: {violations:?}"
    );
}

#[test]
fn dynamic_source_indirection_cannot_use_out_dir() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("lib.rs"),
        "include!(concat!(env!(\"OUT_DIR\"), \"/writer.rs\"));\n",
    )
    .unwrap();

    let violations = collect_source_tree_violations(directory.path(), &[]);

    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("dynamic source indirection is forbidden")),
        "OUT_DIR include escaped writer boundary scan: {violations:?}"
    );
}

#[test]
fn unsupported_source_indirection_syntax_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    for (name, source) in [
        ("brace_include.rs", "include! { \"../writer.rs\" }\n"),
        (
            "commented_include.rs",
            "include/*comment*/!(concat!(env!(\"OUT_DIR\"), \"/writer.rs\"));\n",
        ),
        (
            "commented_path_name.rs",
            "#[path/*comment*/=\"../writer.rs\"] mod writer;\n",
        ),
        (
            "commented_path_value.rs",
            "#[path=/*comment*/\"../writer.rs\"] mod writer;\n",
        ),
    ] {
        std::fs::write(directory.path().join(name), source).unwrap();
    }

    let violations = collect_source_tree_violations(directory.path(), &[]);

    for name in [
        "brace_include.rs",
        "commented_include.rs",
        "commented_path_name.rs",
        "commented_path_value.rs",
    ] {
        assert!(
            violations.iter().any(|violation| violation.contains(name)),
            "unsupported indirection in {name} bypassed boundary scan: {violations:?}"
        );
    }
}

#[test]
fn inline_path_override_cannot_select_a_clean_decoy() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir(directory.path().join("thread")).unwrap();
    std::fs::create_dir(directory.path().join("thread_files")).unwrap();
    std::fs::write(
        directory.path().join("lib.rs"),
        "#[path = \"thread_files\"] mod thread { #[path = \"tls.rs\"] mod local; }\n",
    )
    .unwrap();
    std::fs::write(directory.path().join("thread/tls.rs"), "").unwrap();
    std::fs::write(
        directory.path().join("thread_files/tls.rs"),
        "fn bypass(native: &dyn Store, claim: Claim) { native.delete_version(claim); }\n",
    )
    .unwrap();

    let violations = collect_source_tree_violations(directory.path(), &[]);

    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("thread_files/tls.rs")
                && violation.contains("delete_version")),
        "inline module path override selected a clean decoy: {violations:?}"
    );
}

#[test]
fn raw_identifier_cannot_hide_writer_call() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("lib.rs"),
        "fn bypass(native: &dyn Store, claim: Claim) { native.r#create_version(claim); }\n",
    )
    .unwrap();

    let violations = collect_source_tree_violations(directory.path(), &[]);

    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("create_version")),
        "raw identifier bypassed writer boundary scan: {violations:?}"
    );
}

#[test]
fn writer_fixture_exception_requires_file_level_test_cfg() {
    let directory = tempfile::tempdir().unwrap();
    let fixture = directory.path().join("fixture.rs");
    std::fs::write(&fixture, "fn fixture() { native.create_version(claim); }\n").unwrap();

    let violations = collect_source_tree_violations(directory.path(), &["fixture.rs"]);
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("must begin with #![cfg(test)]")),
        "ungated writer fixture bypassed boundary scan: {violations:?}"
    );

    std::fs::write(
        fixture,
        "#![cfg(test)]\nfn fixture() { native.create_version(claim); }\n",
    )
    .unwrap();
    assert!(collect_source_tree_violations(directory.path(), &["fixture.rs"]).is_empty());
}
