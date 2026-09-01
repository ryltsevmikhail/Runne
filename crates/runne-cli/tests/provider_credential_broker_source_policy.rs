#[path = "provider_credential_broker_source_policy/branch_audit.rs"]
mod branch_audit;
#[path = "provider_credential_broker_source_policy/claim_source_audit.rs"]
mod claim_source_audit;
#[path = "provider_credential_broker_source_policy/source_reference_audit.rs"]
mod source_reference_audit;
#[path = "provider_credential_broker_source_policy/source_substitution_mutations.rs"]
mod source_substitution_mutations;
#[path = "provider_credential_broker_source_policy/source_tree_audit.rs"]
mod source_tree_audit;
#[path = "provider_credential_broker_source_policy/source_tree_helpers.rs"]
mod source_tree_helpers;

use branch_audit::broker_branch_violations;
use source_tree_audit::source_tree_violations;

const BROKER_SOURCE: &str = include_str!("../src/cli/provider_credential_broker.rs");

#[test]
fn broker_has_only_the_exact_macos_and_non_macos_platform_branches() {
    assert!(
        broker_branch_violations(BROKER_SOURCE).is_empty(),
        "{:#?}",
        broker_branch_violations(BROKER_SOURCE)
    );
}

#[test]
fn broker_branch_policy_rejects_platform_and_ingress_mutations() {
    let cases = [
        (
            "Unix-wide receive",
            replace_once(
                BROKER_SOURCE,
                "#[cfg(target_os = \"macos\")]",
                "#[cfg(unix)]",
            ),
        ),
        (
            "Linux-only fallback",
            replace_once(
                BROKER_SOURCE,
                "#[cfg(not(target_os = \"macos\"))]",
                "#[cfg(target_os = \"linux\")]",
            ),
        ),
        (
            "discarded handoff",
            replace_once(BROKER_SOURCE, "let handoff =", "let _ ="),
        ),
        (
            "wrong ingress error",
            replace_first(
                BROKER_SOURCE,
                "CliError::CredentialOperation",
                "CliError::UnsupportedCredentialBackend",
            ),
        ),
        (
            "wrong pinned observation error",
            replace_once(
                BROKER_SOURCE,
                ".observe_current_pinned_writer_session()\n            .map_err(|_| CliError::CredentialOperation)?;",
                ".observe_current_pinned_writer_session()\n            .map_err(|_| CliError::UnsupportedCredentialBackend)?;",
            ),
        ),
        (
            "missing argv end gate",
            replace_once(BROKER_SOURCE, "expect_end(&arguments)?;", ""),
        ),
        (
            "cfg-hidden argv end gate",
            replace_once(
                BROKER_SOURCE,
                "expect_end(&arguments)?;",
                "#[cfg(any())]\n    expect_end(&arguments)?;",
            ),
        ),
        (
            "cfg-hidden handoff",
            replace_once(
                BROKER_SOURCE,
                "let handoff =",
                "#[cfg(any())]\n        let handoff =",
            ),
        ),
        (
            "non-macOS stdin read",
            replace_once(
                BROKER_SOURCE,
                "#[cfg(not(target_os = \"macos\"))]\n    {",
                "#[cfg(not(target_os = \"macos\"))]\n    {\n        let _ = std::io::stdin();",
            ),
        ),
        (
            "wrong post-handoff result",
            replace_first(
                BROKER_SOURCE,
                "Err(CliError::UnsupportedCredentialBackend)",
                "Err(CliError::CredentialOperation)",
            ),
        ),
    ];
    let accepted: Vec<_> = cases
        .into_iter()
        .filter_map(|(label, source)| {
            broker_branch_violations(&source)
                .is_empty()
                .then_some(label)
        })
        .collect();
    assert!(accepted.is_empty(), "policy accepted {accepted:?}");
}

#[test]
fn complete_cli_source_tree_has_no_raw_or_alternate_stdin_receiver() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let violations = source_tree_violations(&root);
    assert!(violations.is_empty(), "{violations:#?}");
}

#[test]
fn recursive_source_policy_rejects_a_nested_raw_receiver() {
    let directory = tempfile::tempdir().unwrap();
    let nested = directory.path().join("nested/deeper");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(
        nested.join("receiver.rs"),
        "fn bypass() { let _ = libc::recvmsg(0, std::ptr::null_mut(), 0); }",
    )
    .unwrap();
    let violations = source_tree_violations(directory.path());
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("recvmsg")),
        "nested receiver escaped scan: {violations:#?}"
    );
}

#[test]
fn recursive_source_policy_scans_included_non_rust_fragments() {
    let directory = tempfile::tempdir().unwrap();
    let nested = directory.path().join("nested");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(
        directory.path().join("main.rs"),
        "fn bypass() { include!(\"nested/receiver.inc\"); }",
    )
    .unwrap();
    std::fs::write(
        nested.join("receiver.inc"),
        "let _ = libc::recvmsg(0, std::ptr::null_mut(), 0);",
    )
    .unwrap();
    let violations = source_tree_violations(directory.path());
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("recvmsg")),
        "included fragment escaped scan: {violations:#?}"
    );
}

#[test]
fn recursive_source_policy_rejects_nested_includes_in_fragments() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("main.rs"),
        "fn bypass() { include!(\"receiver.inc\"); }",
    )
    .unwrap();
    std::fs::write(
        directory.path().join("receiver.inc"),
        "include!(\"unscanned.txt\");",
    )
    .unwrap();
    std::fs::write(
        directory.path().join("unscanned.txt"),
        "let _ = libc::recvmsg(0, std::ptr::null_mut(), 0);",
    )
    .unwrap();
    let violations = source_tree_violations(directory.path());
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("forbidden include")),
        "nested include escaped fragment scan: {violations:#?}"
    );
}

#[test]
#[cfg(unix)]
fn recursive_source_policy_rejects_symbolic_link_sources() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("src");
    std::fs::create_dir(&root).unwrap();
    let outside = directory.path().join("receiver.rs");
    std::fs::write(&outside, "fn bypass() {}").unwrap();
    std::os::unix::fs::symlink(outside, root.join("receiver.rs")).unwrap();
    let violations = source_tree_violations(&root);
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("symbolic link")),
        "symbolic link source escaped scan: {violations:#?}"
    );
}

#[test]
fn recursive_source_policy_rejects_out_of_tree_source_references() {
    let cases = [
        (
            "include reference escapes",
            "fn bypass() { include!(\"../outside.inc\"); }",
        ),
        (
            "path attribute escapes",
            "#[path = \"../outside.rs\"] mod bypass;",
        ),
        (
            "include reference must contain one literal",
            "fn bypass() { include!(concat!(\"nested/\", \"outside.rs\")); }",
        ),
        (
            "path attribute escapes",
            "#[path = \"C:\\\\outside.rs\"] mod bypass;",
        ),
        (
            "conditional path attribute is forbidden",
            "#[cfg_attr(any(), path = \"nested/outside.rs\")] mod bypass;",
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
            "{expected} bypass escaped scan: {violations:#?}"
        );
    }
}

#[test]
fn recursive_source_policy_rejects_stdin_aliases_and_moved_authority_receive() {
    let cases = [
        (
            "forbidden stdin import or alias",
            "use std::io::stdin as inherited; fn bypass() { let _ = inherited(); }",
        ),
        (
            "forbidden stdin call path",
            "use std::io::*; fn bypass() { let _ = stdin(); }",
        ),
        (
            "forbidden stdin identifier outside a reviewed call",
            "use std::io::*; fn bypass() { let inherited = stdin; let _ = inherited(); }",
        ),
        (
            "forbidden receive_from_stdin call path",
            "fn bypass() { let _ = Authority::receive_from_stdin(); }",
        ),
        (
            "forbidden observe_current_pinned_writer_session call path",
            "fn bypass(handoff: Handoff) { let _ = handoff.observe_current_pinned_writer_session(); }",
        ),
        (
            "forbidden stdin macro token",
            "fn bypass() { passthrough!(std::io::stdin()); }",
        ),
    ];
    for (expected, source) in cases {
        let directory = tempfile::tempdir().unwrap();
        let nested = directory.path().join("nested/deeper");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("receiver.rs"), source).unwrap();
        let violations = source_tree_violations(directory.path());
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains(expected)),
            "{expected} bypass escaped scan: {violations:#?}"
        );
    }
}

fn replace_once(source: &str, old: &str, new: &str) -> String {
    assert_eq!(source.matches(old).count(), 1, "fixture drift for {old}");
    source.replacen(old, new, 1)
}

fn replace_first(source: &str, old: &str, new: &str) -> String {
    assert!(source.contains(old), "fixture drift for {old}");
    source.replacen(old, new, 1)
}
