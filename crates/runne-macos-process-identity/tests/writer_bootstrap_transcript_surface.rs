#![cfg(target_os = "macos")]

use runne_api::{PendingSignedInstalledReleaseMetadataV2, VerifiedSignedInstalledReleaseV2};
use runne_macos_process_identity::{
    MacOsPackagedWriterObservationError, MacOsPendingProvisionalReleaseMatchV1,
    MacOsPendingProvisionalWriterSessionV1, MacOsPendingWriterBootstrapTranscriptV1,
    MacOsUntrustedWriterEndpointHandoffV1,
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
    let matched: fn(
        MacOsPendingProvisionalReleaseMatchV1,
        VerifiedSignedInstalledReleaseV2,
    ) -> Result<
        MacOsPendingProvisionalWriterSessionV1,
        MacOsPackagedWriterObservationError,
    > = MacOsPendingProvisionalReleaseMatchV1::match_signed_release;
    let _ = (observe, release, matched);
}

#[test]
fn bootstrap_pending_values_are_opaque_and_non_authoritative() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let transcript =
        std::fs::read_to_string(root.join("src/writer_bootstrap_transcript.rs")).unwrap();
    let provisional =
        std::fs::read_to_string(root.join("src/provisional_writer_session.rs")).unwrap();
    let source = format!("{transcript}\n{provisional}");
    let facade = std::fs::read_to_string(root.join("src/lib.rs")).unwrap();

    for name in [
        "MacOsPendingWriterBootstrapTranscriptV1",
        "MacOsPendingProvisionalReleaseMatchV1",
        "MacOsPendingProvisionalWriterSessionV1",
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
    assert!(facade.contains("MacOsPendingProvisionalWriterSessionV1"));
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
    assert_eq!(source.matches("pub fn match_signed_release(").count(), 1);
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

#[test]
fn provisional_writer_session_match_uses_every_retained_fact_before_its_sole_constructor() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let transition =
        std::fs::read_to_string(root.join("src/provisional_writer_session.rs")).unwrap();
    let signing = std::fs::read_to_string(root.join("src/signed_code_identity.rs")).unwrap();
    let observation =
        std::fs::read_to_string(root.join("src/packaged_writer_observation.rs")).unwrap();

    for predicate in [
        "matches_desktop_digest",
        "matches_writer_digest",
        "matches_daemon_digest",
        "matches_contract_digest",
        "matches_pending_issue_ticket",
        "matches_handoff",
        "matches_live_processes",
        "matches_provisional_release_binding",
        "release_binding_matcher",
        "match_retained_code_identities",
    ] {
        assert!(
            transition.contains(predicate),
            "missing predicate: {predicate}"
        );
    }
    for predicate in [
        "matches_desktop_code_identity",
        "matches_writer_code_identity",
        "matches_daemon_code_identity",
    ] {
        assert!(
            signing.contains(predicate),
            "missing predicate: {predicate}"
        );
    }
    assert!(signing.contains("struct MatchedSignedCodeIdentity"));
    assert!(signing.contains("Result<MatchedSignedCodeIdentity"));
    for helper in ["fn match_static_code(", "fn match_dynamic_code("] {
        let body = signing.split(helper).nth(1).unwrap();
        let owner_match = body.find("match_release_code_identity").unwrap();
        let requirement_check = body.find("matched.check_").unwrap();
        assert!(owner_match < requirement_check);
    }
    let owner_matcher = signing
        .split("fn match_release_code_identity(")
        .nth(1)
        .unwrap();
    let first_owner_bool = owner_matcher.find("release.matches_").unwrap();
    let matched_type = owner_matcher
        .find("then_some(MatchedSignedCodeIdentity")
        .unwrap();
    assert!(first_owner_bool < matched_type);

    let match_start = transition.find("pub fn match_signed_release(").unwrap();
    let final_revalidation = transition[match_start..]
        .find("revalidate_for_provisional_session")
        .unwrap()
        + match_start;
    let constructor = transition[match_start..]
        .find("MacOsPendingProvisionalWriterSessionV1 {")
        .unwrap()
        + match_start;
    assert!(final_revalidation < constructor);
    assert_eq!(
        transition
            .matches("MacOsPendingProvisionalWriterSessionV1 {")
            .count(),
        2
    );

    assert!(observation.contains("peer.process_start_digest() == peer_process.start_digest()"));
    let revalidate = observation
        .split("fn revalidate_for_provisional_session")
        .nth(1)
        .unwrap();
    let first_peer = revalidate.find("revalidate_same_peer").unwrap();
    let package = revalidate.find("package.revalidate").unwrap();
    let writer = revalidate.find("self_process.revalidate_self").unwrap();
    let daemon = revalidate.find("peer_process.revalidate_peer").unwrap();
    let last_peer = revalidate.rfind("revalidate_same_peer").unwrap();
    assert!(first_peer < package && package < writer && writer < daemon && daemon < last_peer);
}

#[test]
fn final_race_hooks_are_test_only_and_production_surface_stays_exact() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let observation =
        std::fs::read_to_string(root.join("src/packaged_writer_observation.rs")).unwrap();
    let provisional =
        std::fs::read_to_string(root.join("src/provisional_writer_session.rs")).unwrap();
    let artifact =
        std::fs::read_to_string(root.join("src/packaged_writer_observation/artifact.rs")).unwrap();
    let process =
        std::fs::read_to_string(root.join("src/packaged_writer_observation/process.rs")).unwrap();
    let code =
        std::fs::read_to_string(root.join("src/packaged_writer_observation/security_code.rs"))
            .unwrap();
    let peer = std::fs::read_to_string(root.join("src/local_peer.rs")).unwrap();

    for (source, hook) in [
        (&artifact, "test_only_corrupt_digest"),
        (&process, "test_only_corrupt_start"),
        (&process, "test_only_corrupt_native_code"),
        (&code, "test_only_corrupt_main_executable"),
        (&peer, "test_only_corrupt_process_start"),
        (&observation, "test_only_inject_final_race"),
        (&provisional, "test_only_revalidate_after_final_race"),
    ] {
        let hook_position = source
            .find(hook)
            .unwrap_or_else(|| panic!("missing {hook}"));
        let cfg_position = source[..hook_position].rfind("#[cfg(test)]").unwrap();
        let guarded_prefix = &source[cfg_position..hook_position];
        assert!(guarded_prefix.contains("fn "));
        assert!(!guarded_prefix.contains('}'), "{hook} is not test-only");
    }

    let production_transition = provisional
        .split("pub fn match_signed_release(")
        .nth(1)
        .unwrap()
        .split("#[cfg(test)]")
        .next()
        .unwrap();
    assert!(!production_transition.contains("test_only_"));
    assert_eq!(
        provisional
            .matches("MacOsPendingProvisionalWriterSessionV1 {")
            .count(),
        2
    );
    for forbidden in ["SystemTime", "pub trait", "pub fn mint", "into_authority"] {
        assert!(!production_transition.contains(forbidden));
    }
}
