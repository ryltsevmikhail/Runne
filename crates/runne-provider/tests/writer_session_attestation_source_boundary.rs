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
fn attestation_exposes_only_the_four_boolean_matchers() {
    let root = crate_root();
    let attestation =
        production_source(&root.join("src/credential/enrollment/protocol/session_attestation.rs"));
    let matchers = production_source(
        &root.join("src/credential/enrollment/protocol/session_attestation/matchers.rs"),
    );
    assert_eq!(matchers.matches("pub fn ").count(), 4);
    for name in [
        "matches_pending_issue_ticket",
        "matches_handoff",
        "matches_live_processes",
        "matches_provisional_release_binding",
    ] {
        assert_eq!(matchers.matches(name).count(), 1, "missing matcher {name}");
    }
    for forbidden in [
        "pub fn binding_digest",
        "pub fn ticket_claims",
        "pub fn runtime_claims",
        "pub fn process_claims",
        "pub fn channel_binding",
        "pub fn publication_public_key",
        "matches_current_time",
        "now:",
        "clock:",
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
