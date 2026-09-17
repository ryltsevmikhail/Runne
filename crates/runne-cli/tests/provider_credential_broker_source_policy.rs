#[path = "provider_credential_broker_source_policy/branch_audit.rs"]
mod branch_audit;
#[path = "provider_credential_broker_source_policy/branch_mutations.rs"]
mod branch_mutations;
#[path = "provider_credential_broker_source_policy/claim_source_audit.rs"]
mod claim_source_audit;
#[path = "provider_credential_broker_source_policy/disclosure_sink_audit.rs"]
mod disclosure_sink_audit;
#[path = "provider_credential_broker_source_policy/disclosure_stage_binding.rs"]
mod disclosure_stage_binding;
#[path = "provider_credential_broker_source_policy/source_reference_audit.rs"]
mod source_reference_audit;
#[path = "provider_credential_broker_source_policy/source_substitution_mutations.rs"]
mod source_substitution_mutations;
#[path = "provider_credential_broker_source_policy/source_tree_audit.rs"]
mod source_tree_audit;
#[path = "provider_credential_broker_source_policy/source_tree_helpers.rs"]
mod source_tree_helpers;
#[path = "provider_credential_broker_source_policy/stage_diagnostics_audit.rs"]
mod stage_diagnostics_audit;

use branch_audit::broker_branch_violations;
use disclosure_sink_audit::{broker_disclosure_sink_violations, disclosure_sink_violations};
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
fn complete_cli_source_tree_has_no_raw_or_alternate_stdin_receiver() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let violations = source_tree_violations(&root);
    assert!(violations.is_empty(), "{violations:#?}");
}

#[test]
fn provider_credential_broker_production_sources_have_no_disclosure_sinks() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/cli/provider_credential_broker.rs");
    let violations = broker_disclosure_sink_violations(&root);
    assert!(violations.is_empty(), "{violations:#?}");
}

#[test]
fn provider_credential_broker_disclosure_sink_mutations_are_rejected() {
    for (expected, source) in [
        ("print macro", "fn leak() { println!(\"secret\"); }"),
        ("print macro", "fn leak() { eprintln!(\"secret\"); }"),
        ("debug macro", "fn leak(secret: &str) { dbg!(secret); }"),
        ("panic sink", "fn leak() { panic!(\"secret\"); }"),
        (
            "print macro",
            "use std::println as report; fn leak() { report!(\"secret\"); }",
        ),
        (
            "debug macro",
            "use std::dbg as inspect; fn leak(secret: &str) { inspect!(secret); }",
        ),
        (
            "panic sink",
            "use std::panic as stop; fn leak() { stop!(\"secret\"); }",
        ),
        ("log sink", "fn leak() { log::error!(\"secret\"); }"),
        ("tracing sink", "fn leak() { tracing::error!(\"secret\"); }"),
        ("stdout/stderr sink", "fn leak() { std::io::stdout(); }"),
        ("stdout/stderr sink", "fn leak() { std::io::stderr(); }"),
    ] {
        let violations = disclosure_sink_violations("mutation.rs", source);
        assert!(
            violations
                .iter()
                .any(|violation| violation.contains(expected)),
            "{expected} mutation escaped: {violations:#?}"
        );
    }
}

#[test]
fn provider_credential_broker_sink_policy_does_not_skip_mixed_test_cfg() {
    let directory = tempfile::tempdir().expect("policy fixture");
    let root = directory.path().join("broker.rs");
    let modules = directory.path().join("broker");
    std::fs::create_dir(&modules).expect("module directory");
    std::fs::write(&root, "#[cfg(any(test, target_os = \"macos\"))] mod leaky;")
        .expect("broker fixture");
    std::fs::write(
        modules.join("leaky.rs"),
        "fn leak() { println!(\"secret\"); }",
    )
    .expect("leaky fixture");

    let violations = broker_disclosure_sink_violations(&root);
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains("print macro")),
        "mixed production cfg escaped: {violations:#?}"
    );
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
