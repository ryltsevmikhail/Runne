#[path = "provider_credential_broker_source_policy/branch_audit.rs"]
mod branch_audit;
#[path = "provider_credential_broker_source_policy/source_tree_audit.rs"]
mod source_tree_audit;

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
            replace_once(BROKER_SOURCE, "let _handoff =", "let _ ="),
        ),
        (
            "wrong ingress error",
            replace_once(
                BROKER_SOURCE,
                "CliError::CredentialOperation",
                "CliError::UnsupportedCredentialBackend",
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
                "let _handoff =",
                "#[cfg(any())]\n        let _handoff =",
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
fn recursive_source_policy_rejects_stdin_aliases_and_moved_authority_receive() {
    let cases = [
        (
            "forbidden stdin import or alias",
            "use std::io::stdin as inherited; fn bypass() { let _ = inherited(); }",
        ),
        (
            "forbidden receive_from_stdin call path",
            "fn bypass() { let _ = Authority::receive_from_stdin(); }",
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
