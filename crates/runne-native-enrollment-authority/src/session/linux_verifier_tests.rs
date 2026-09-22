#![cfg(test)]

//! B9 verifier fixture tests: a REAL signed V2 attestation (fixture signer,
//! deterministic bounded freshness window around the real clock) verified
//! against independently RETAINED expectations; every mismatch — including a
//! foreign signer's internally-consistent payload — rejects BEFORE any
//! effect capability exists.

use std::os::unix::net::UnixStream;

use runne_provider::daemon_credential_publication::CredentialWriterSessionAttestationSigner;
use runne_provider::{
    BrokerChannelBinding, CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerFrame,
    CredentialBrokerFrameCodec, CredentialBrokerTarget, CredentialEnrollmentAuthorityPair,
    CredentialFence, CredentialInstallationOwnerId, CredentialIssueTicketBindingV1,
    CredentialLifecycleRevision, CredentialOperationAction, CredentialOperationId,
    CredentialTicketAttempt, CredentialVersionRef, CredentialWriterSessionAttestationClaimsV1,
    CredentialWriterSessionAttestationV2Codec, CredentialWriterSessionProcessClaimsV1,
    CredentialWriterSessionRuntimeClaimsV1, CredentialWriterSessionTicketClaimsV1,
    PendingCredentialIssueTicketV1, ProviderId, RawCredentialTicket,
};

use super::super::AuthenticatedProviderCredentialWriterSession;
use super::linux_verifier::authenticate_linux_writer_session;

const LIVE_START: [u8; 32] = [21; 32];
const DAEMON_START: [u8; 32] = [23; 32];
const DAEMON_IMAGE: [u8; 32] = [24; 32];
const LIVE_IMAGE: [u8; 32] = [22; 32];
const RETAINED_HANDOFF: [u8; 32] = [25; 32];
const RELEASE_TUPLE: [u8; 32] = [26; 32];
const CHANNEL_BYTES: [u8; 32] = [9; 32];
const LAUNCH_GENERATION: u64 = 7;

struct Fixture {
    publication_key: [u8; 32],
    channel: BrokerChannelBinding,
    encoded_ticket: Vec<u8>,
    attestation_bytes: Vec<u8>,
}

fn digest(bytes: [u8; 32]) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured(bytes).unwrap()
}

#[path = "linux_ordinary_tests.rs"]
mod ordinary;

fn fixture(expired: bool, signer: CredentialWriterSessionAttestationSigner) -> Fixture {
    fixture_version(expired, signer, true)
}

fn fixture_version(
    expired: bool,
    signer: CredentialWriterSessionAttestationSigner,
    qualified: bool,
) -> Fixture {
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let channel = measurements.broker_channel_binding(CHANNEL_BYTES).unwrap();
    let provider = ProviderId::new("openai").unwrap();
    let operation_id = CredentialOperationId::from_bytes([31; 16]).unwrap();
    let attempt = CredentialTicketAttempt::new(1).unwrap();
    let command = CredentialBrokerCommand::new(
        operation_id,
        attempt,
        provider.clone(),
        CredentialOperationAction::Pair,
        CredentialBrokerTarget::Version(CredentialVersionRef::new(provider, 1).unwrap()),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        None,
    )
    .unwrap();
    let frame = CredentialBrokerFrame::IssueTicket {
        operation_id,
        attempt,
        ticket: RawCredentialTicket::generate().unwrap(),
        channel_binding: CHANNEL_BYTES,
        binding: digest([3; 32]),
        command,
    };
    let attested_binding = CredentialIssueTicketBindingV1::from_issue_ticket(&frame).unwrap();
    let encoded = CredentialBrokerFrameCodec::encode(frame).unwrap();
    let encoded_ticket = encoded.to_vec();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let (issued, expires) = if expired {
        (now - 7200, now - 3600)
    } else {
        (now - 60, now + 600)
    };
    let claims = CredentialWriterSessionAttestationClaimsV1::new(
        CredentialWriterSessionTicketClaimsV1::new(
            operation_id,
            attempt,
            attested_binding,
            digest([3; 32]),
            CredentialInstallationOwnerId::from_bytes([2; 32]).unwrap(),
            digest([5; 32]),
            issued,
            expires,
        )
        .unwrap(),
        CredentialWriterSessionRuntimeClaimsV1::new(
            digest([4; 32]),
            digest([5; 32]),
            digest([6; 32]),
            1,
            1,
            digest(RELEASE_TUPLE),
        )
        .unwrap(),
        CredentialWriterSessionProcessClaimsV1::new(
            digest(RETAINED_HANDOFF),
            digest(LIVE_START),
            digest(LIVE_IMAGE),
            digest([27; 32]),
            digest(DAEMON_START),
            digest(DAEMON_IMAGE),
        )
        .unwrap(),
    );
    let publication_key = signer.public_key();
    let attestation_bytes = if qualified {
        let (attestation, _) = signer
            .sign_qualified(claims, LAUNCH_GENERATION, [41; 32], [42; 32])
            .unwrap();
        CredentialWriterSessionAttestationV2Codec::encode(&attestation).to_vec()
    } else {
        let (attestation, _) = signer.sign(claims).unwrap();
        runne_provider::CredentialWriterSessionAttestationCodec::encode(&attestation).to_vec()
    };
    Fixture {
        publication_key,
        channel,
        encoded_ticket,
        attestation_bytes,
    }
}

impl Fixture {
    fn pending(&self) -> PendingCredentialIssueTicketV1 {
        let ticket =
            PendingCredentialIssueTicketV1::read_from(&mut self.encoded_ticket.as_slice()).unwrap();
        if self.attestation_bytes.first() == Some(&2) {
            if let Ok(record) = CredentialWriterSessionAttestationV2Codec::decode_and_verify(
                &self.attestation_bytes,
                self.publication_key,
            ) {
                return ticket.with_qualified_attestation(record);
            }
        }
        ticket
    }
}

fn authenticate(
    fixture: &Fixture,
    key: [u8; 32],
    handoff: [u8; 32],
    live_start: [u8; 32],
    live_image: [u8; 32],
    tuple: [u8; 32],
) -> Result<AuthenticatedProviderCredentialWriterSession, &'static str> {
    let (control, _) = UnixStream::pair().unwrap();
    authenticate_linux_writer_session(
        &fixture.attestation_bytes,
        key,
        &fixture.channel,
        handoff,
        live_start,
        live_image,
        tuple,
        fixture.channel.clone(),
        fixture.pending(),
        control,
        std::path::PathBuf::from("/writer"),
        std::path::PathBuf::from("/reader"),
    )
}

#[test]
fn verified_fixture_mints_a_session_whose_parts_bind_the_ticket() {
    let signer = CredentialWriterSessionAttestationSigner::generate(CHANNEL_BYTES).unwrap();
    let fixture = fixture(false, signer);
    let session = authenticate(
        &fixture,
        fixture.publication_key,
        RETAINED_HANDOFF,
        LIVE_START,
        LIVE_IMAGE,
        RELEASE_TUPLE,
    )
    .expect("valid signed fixture under retained authority");
    let (claim, effect) = session.split();
    let (issuer, control, _channel, _ticket) = claim
        .into_linux_claim_parts()
        .expect("verified claim parts");
    drop((issuer, control));
    let (_, writer, reader) = effect
        .into_linux_effect_parts()
        .expect("verified effect parts");
    assert_eq!(writer, std::path::PathBuf::from("/writer"));
    assert_eq!(reader, std::path::PathBuf::from("/reader"));
}

#[test]
fn foreign_signer_internally_consistent_payload_is_denied() {
    let foreign = CredentialWriterSessionAttestationSigner::generate(CHANNEL_BYTES).unwrap();
    let fixture = fixture(false, foreign);
    let retained_key = CredentialWriterSessionAttestationSigner::generate(CHANNEL_BYTES)
        .unwrap()
        .public_key();
    assert!(
        authenticate(
            &fixture,
            retained_key,
            RETAINED_HANDOFF,
            LIVE_START,
            LIVE_IMAGE,
            RELEASE_TUPLE,
        )
        .is_err(),
        "a foreign signer must never authenticate against the retained key"
    );
}

#[test]
fn wrong_retained_channel_is_denied() {
    let signer = CredentialWriterSessionAttestationSigner::generate(CHANNEL_BYTES).unwrap();
    let fixture = fixture(false, signer);
    let (_, other_measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let other = other_measurements.broker_channel_binding([99; 32]).unwrap();
    let (control, _) = UnixStream::pair().unwrap();
    assert!(
        authenticate_linux_writer_session(
            &fixture.attestation_bytes,
            fixture.publication_key,
            &other,
            RETAINED_HANDOFF,
            LIVE_START,
            LIVE_IMAGE,
            RELEASE_TUPLE,
            fixture.channel.clone(),
            fixture.pending(),
            control,
            std::path::PathBuf::from("/w"),
            std::path::PathBuf::from("/r"),
        )
        .is_err(),
        "a mismatched retained channel binding must deny"
    );
}

#[test]
fn wrong_handoff_start_image_daemon_or_tuple_denies() {
    let signer = CredentialWriterSessionAttestationSigner::generate(CHANNEL_BYTES).unwrap();
    let fixture = fixture(false, signer);
    let key = fixture.publication_key;
    for case in [
        ([77; 32], LIVE_START, LIVE_IMAGE, RELEASE_TUPLE),
        (RETAINED_HANDOFF, [78; 32], LIVE_IMAGE, RELEASE_TUPLE),
        (RETAINED_HANDOFF, LIVE_START, [79; 32], RELEASE_TUPLE),
        (RETAINED_HANDOFF, LIVE_START, LIVE_IMAGE, [82; 32]),
    ] {
        assert!(
            authenticate(&fixture, key, case.0, case.1, case.2, case.3).is_err(),
            "mismatched retained facts must deny before any effect"
        );
    }
}

#[test]
fn expired_attestation_is_denied() {
    let signer = CredentialWriterSessionAttestationSigner::generate(CHANNEL_BYTES).unwrap();
    let fixture = fixture(true, signer);
    assert!(
        authenticate(
            &fixture,
            fixture.publication_key,
            RETAINED_HANDOFF,
            LIVE_START,
            LIVE_IMAGE,
            RELEASE_TUPLE,
        )
        .is_err(),
        "an expired attestation must deny"
    );
}
