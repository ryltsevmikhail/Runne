use std::path::{Path, PathBuf};

fn crate_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_owned()
}

fn production_source(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()))
        .lines()
        .filter(|line| !line.trim_start().starts_with("///"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn rust_sources(directory: &Path, output: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).expect("source directory") {
        let path = entry.expect("source entry").path();
        if path.is_dir() {
            let is_test_tree = path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().contains("test"));
            if !is_test_tree {
                rust_sources(&path, output);
            }
        } else if path.extension().is_some_and(|extension| extension == "rs")
            && path
                .file_stem()
                .is_none_or(|stem| !stem.to_string_lossy().contains("test"))
        {
            output.push(path);
        }
    }
}

#[test]
fn pending_ticket_has_one_opaque_reader_and_no_escape_surface() {
    let path =
        crate_root().join("src/credential/enrollment/protocol/session_attestation/issue_ticket.rs");
    let source = production_source(&path);

    assert_eq!(
        source
            .matches("pub struct PendingCredentialIssueTicketV1")
            .count(),
        1
    );
    assert_eq!(
        source.matches("pub fn read_from<R: std::io::Read>").count(),
        1
    );
    assert_eq!(
        source
            .matches("CredentialBrokerFrameCodec::read_from(reader)?")
            .count(),
        1
    );
    assert_eq!(source.matches("Ok(Self { frame, binding })").count(), 1);
    let fields = source
        .split_once("pub struct PendingCredentialIssueTicketV1 {")
        .and_then(|(_, rest)| rest.split_once('}'))
        .map(|(fields, _)| fields)
        .expect("pending ticket fields");
    assert!(fields.contains("frame: CredentialBrokerFrame"));
    assert!(fields.contains("binding: CredentialIssueTicketBindingV1"));
    assert!(
        !fields.contains("pub"),
        "pending fields must remain private"
    );
    for forbidden in [
        "impl Clone for PendingCredentialIssueTicketV1",
        "impl Copy for PendingCredentialIssueTicketV1",
        "impl Debug for PendingCredentialIssueTicketV1",
        "impl Default for PendingCredentialIssueTicketV1",
        "Serialize for PendingCredentialIssueTicketV1",
        "Deserialize<'",
        "AsFd for PendingCredentialIssueTicketV1",
        "AsRawFd for PendingCredentialIssueTicketV1",
        "IntoRawFd for PendingCredentialIssueTicketV1",
        "pub fn new",
        "pub fn from_parts",
        "impl From<",
        "impl Into<",
        "pub fn frame",
        "pub fn binding",
        "pub fn digest",
        "pub trait",
    ] {
        assert!(
            !source.contains(forbidden),
            "pending ticket exposes forbidden surface: {forbidden}"
        );
    }
}

#[test]
fn attestation_exposes_only_locked_opaque_match_surface() {
    let root = crate_root();
    let attestation =
        production_source(&root.join("src/credential/enrollment/protocol/session_attestation.rs"));
    let matchers = production_source(
        &root.join("src/credential/enrollment/protocol/session_attestation/matchers.rs"),
    );
    assert_eq!(matchers.matches("pub fn ").count(), 5);
    for name in [
        "matches_pending_issue_ticket",
        "matches_handoff",
        "matches_live_processes",
        "release_binding_expectation",
        "is_current_now",
    ] {
        assert_eq!(matchers.matches(name).count(), 1, "missing matcher {name}");
    }
    assert_eq!(matchers.matches("-> bool").count(), 5);
    assert!(
        matchers.contains("pub fn release_binding_expectation(&self) -> DigestEqualityMatcherV1")
    );
    assert!(matchers.contains("pub fn is_current_now(&self) -> bool"));
    for forbidden in [
        "pub fn binding_digest",
        "pub fn ticket_claims",
        "pub fn runtime_claims",
        "pub fn process_claims",
        "pub fn channel_binding",
        "pub fn publication_public_key",
        "matches_current_time",
        "pub fn is_current_now(&self,",
        "pub fn release_binding_expectation(&self,",
    ] {
        assert!(
            !attestation.contains(forbidden) && !matchers.contains(forbidden),
            "attestation exposes forbidden surface: {forbidden}"
        );
    }
    for facade in [
        "src/credential/enrollment/protocol.rs",
        "src/credential/enrollment.rs",
        "src/lib.rs",
    ] {
        let source = production_source(&root.join(facade));
        assert_eq!(
            source.matches("PendingCredentialIssueTicketV1").count(),
            1,
            "unexpected selective export in {facade}"
        );
    }
}

#[test]
fn macos_consumer_never_recovers_release_binding_from_attestation_wire_bytes() {
    let provider = crate_root();
    let workspace = provider.parent().and_then(Path::parent).unwrap();
    let mut sources = Vec::new();
    rust_sources(
        &workspace.join("crates/runne-macos-process-identity/src"),
        &mut sources,
    );
    for path in sources {
        let source = production_source(&path);
        for forbidden in [
            "CredentialWriterSessionAttestationCodec::encode",
            "265..297",
        ] {
            assert!(
                !source.contains(forbidden),
                "{} bypasses opaque release binding via {forbidden}",
                path.display(),
            );
        }
    }
}
