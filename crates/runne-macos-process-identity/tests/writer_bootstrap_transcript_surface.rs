#![cfg(target_os = "macos")]

use runne_api::PendingSignedInstalledReleaseMetadataV2;
use runne_macos_process_identity::{
    MacOsPackagedWriterObservationError, MacOsPendingProvisionalReleaseMatchV1,
    MacOsPendingWriterBootstrapTranscriptV1, MacOsUntrustedWriterEndpointHandoffV1,
};

#[test]
fn bootstrap_has_only_the_exact_consuming_state_transitions() {
    let observe: fn(
        MacOsUntrustedWriterEndpointHandoffV1,
    ) -> Result<
        MacOsPendingWriterBootstrapTranscriptV1,
        MacOsPackagedWriterObservationError,
    > = MacOsUntrustedWriterEndpointHandoffV1::observe_pending_writer_bootstrap;
    let release: fn(
        MacOsPendingWriterBootstrapTranscriptV1,
    ) -> (
        MacOsPendingProvisionalReleaseMatchV1,
        PendingSignedInstalledReleaseMetadataV2,
    ) = MacOsPendingWriterBootstrapTranscriptV1::into_release_verification;
    let _ = (observe, release);
}

#[test]
fn bootstrap_pending_values_are_opaque_and_non_authoritative() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(root.join("src/writer_bootstrap_transcript.rs")).unwrap();
    let facade = std::fs::read_to_string(root.join("src/lib.rs")).unwrap();

    for name in [
        "MacOsPendingWriterBootstrapTranscriptV1",
        "MacOsPendingProvisionalReleaseMatchV1",
    ] {
        assert_eq!(source.matches(&format!("pub struct {name}")).count(), 1);
        for forbidden in ["Clone for", "Copy for", "Debug for", "Default for"] {
            assert!(
                !source.contains(&format!("{forbidden} {name}")),
                "forbidden {forbidden} {name}"
            );
        }
    }
    assert!(facade.contains("MacOsPendingWriterBootstrapTranscriptV1"));
    assert!(facade.contains("MacOsPendingProvisionalReleaseMatchV1"));
    for forbidden in [
        "#[derive(",
        "pub fn from_parts",
        "pub fn path",
        "pub fn pid",
        "pub fn audit_token",
        "pub fn digest",
        "pub fn frame",
        "pub fn bytes",
        "pub fn control",
        "pub fn verify",
        "pub fn authenticate",
        "pub fn admit",
        "pub fn mint",
        "pub fn into_authority",
        "pub trait",
        "Serialize",
        "Deserialize",
        "AsFd",
        "AsRawFd",
        "IntoRawFd",
        "SystemTime",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden bootstrap surface: {forbidden}"
        );
    }
    assert_eq!(
        source
            .matches("pub fn observe_pending_writer_bootstrap(")
            .count(),
        1
    );
    assert_eq!(
        source.matches("pub fn into_release_verification(").count(),
        1
    );
}

#[test]
fn cheap_peer_prefix_deadline_and_heavy_capture_have_locked_ordering() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = std::fs::read_to_string(root.join("src/writer_bootstrap_transcript.rs")).unwrap();
    let deadline =
        std::fs::read_to_string(root.join("src/writer_bootstrap_transcript/deadline.rs")).unwrap();
    let peer_source = std::fs::read_to_string(root.join("src/local_peer.rs")).unwrap();

    let cheap_peer = source
        .find("let peer = MacOsLocalPeerProcessIdentity::capture")
        .unwrap();
    let reader = source.find("let mut reader = DeadlineReader::new").unwrap();
    let prefix = source.find("let prefix = read_prefix").unwrap();
    let queued = source.find(".reject_queued_input()").unwrap();
    let heavy = source
        .find("CapturedPackagedWriterObservationV1::capture_with_retained_peer")
        .unwrap();
    assert!(cheap_peer < reader && reader < prefix && prefix < queued && queued < heavy);

    let parser = source.split("fn read_prefix").nth(1).unwrap();
    let attestation = parser
        .find("CredentialWriterSessionAttestationCodec::read_from")
        .unwrap();
    let ticket = parser
        .find("PendingCredentialIssueTicketV1::read_from")
        .unwrap();
    let release = parser
        .find("PendingSignedInstalledReleaseMetadataV2::read_from")
        .unwrap();
    assert!(attestation < ticket && ticket < release);

    assert!(source.contains("const PRODUCTION_PREFIX_BUDGET: Duration = Duration::from_secs(1);"));
    for fact in [
        "sockopt::LocalPeerToken",
        "sockopt::LocalPeerPid",
        "sockopt::LocalPeerCred",
        "peer_kill::effective_uid()",
        "MacOsProcessStartIdentity::observe(pid)",
        "socket_identity(stream)?",
    ] {
        assert!(
            peer_source.contains(fact),
            "missing cheap peer fact: {fact}"
        );
    }
    assert_eq!(deadline.matches("checked_add(budget)").count(), 1);
    assert!(deadline.contains("poll("));
    assert!(deadline.contains("MsgFlags::MSG_DONTWAIT"));
    assert!(deadline.contains("MsgFlags::MSG_PEEK"));
    for forbidden in ["thread::sleep", "read_to_end", "read_to_string"] {
        assert!(
            !deadline.contains(forbidden),
            "blocking deadline escape: {forbidden}"
        );
    }
}
