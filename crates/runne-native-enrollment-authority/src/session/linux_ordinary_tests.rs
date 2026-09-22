//! Ordinary V1 uses the same retained identity boundary as qualified V2.
use super::*;

fn verify(fixture: &Fixture) -> Result<AuthenticatedProviderCredentialWriterSession, &'static str> {
    authenticate(
        fixture,
        fixture.publication_key,
        RETAINED_HANDOFF,
        LIVE_START,
        LIVE_IMAGE,
        RELEASE_TUPLE,
    )
}

#[test]
fn ordinary_session_retains_all_identity_checks() {
    let signer = CredentialWriterSessionAttestationSigner::generate(CHANNEL_BYTES).unwrap();
    let mut fixture = fixture_version(false, signer, false);
    let session = verify(&fixture).expect("ordinary signed Linux session");
    let (claim, _) = session.split();
    let (_, _, _, ticket) = claim.into_linux_claim_parts().unwrap();
    assert!(!ticket.is_qualified());
    for (handoff, start, image, tuple) in [
        ([77; 32], LIVE_START, LIVE_IMAGE, RELEASE_TUPLE),
        (RETAINED_HANDOFF, [78; 32], LIVE_IMAGE, RELEASE_TUPLE),
        (RETAINED_HANDOFF, LIVE_START, [79; 32], RELEASE_TUPLE),
        (RETAINED_HANDOFF, LIVE_START, LIVE_IMAGE, [80; 32]),
    ] {
        assert!(
            authenticate(
                &fixture,
                fixture.publication_key,
                handoff,
                start,
                image,
                tuple
            )
            .is_err()
        );
    }
    let foreign = CredentialWriterSessionAttestationSigner::generate(CHANNEL_BYTES).unwrap();
    assert!(
        authenticate(
            &fixture,
            foreign.public_key(),
            RETAINED_HANDOFF,
            LIVE_START,
            LIVE_IMAGE,
            RELEASE_TUPLE
        )
        .is_err()
    );
    let other = fixture_version(false, foreign, false);
    fixture.encoded_ticket = other.encoded_ticket;
    assert!(
        verify(&fixture).is_err(),
        "different exact ticket must deny"
    );
}

#[test]
fn versions_cannot_be_retagged_and_bad_signatures_never_fall_back() {
    for qualified in [false, true] {
        let signer = CredentialWriterSessionAttestationSigner::generate(CHANNEL_BYTES).unwrap();
        let mut fixture = fixture_version(false, signer, qualified);
        assert!(verify(&fixture).is_ok());
        let original = fixture.attestation_bytes.clone();
        fixture.attestation_bytes[0] = if qualified { 1 } else { 2 };
        assert!(verify(&fixture).is_err());
        fixture.attestation_bytes = original;
        *fixture.attestation_bytes.last_mut().unwrap() ^= 1;
        assert!(verify(&fixture).is_err());
        fixture.attestation_bytes.truncate(1);
        assert!(verify(&fixture).is_err());
    }
}

#[test]
fn ordinary_expired_and_wrong_channel_records_are_denied() {
    let signer = CredentialWriterSessionAttestationSigner::generate(CHANNEL_BYTES).unwrap();
    assert!(verify(&fixture_version(true, signer, false)).is_err());
    let signer = CredentialWriterSessionAttestationSigner::generate(CHANNEL_BYTES).unwrap();
    let mut fixture = fixture_version(false, signer, false);
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    fixture.channel = measurements.broker_channel_binding([99; 32]).unwrap();
    assert!(verify(&fixture).is_err());
}

#[test]
fn qualified_record_cannot_mint_an_unqualified_ticket() {
    let signer = CredentialWriterSessionAttestationSigner::generate(CHANNEL_BYTES).unwrap();
    let fixture = fixture(false, signer);
    let (control, _) = UnixStream::pair().unwrap();
    let unbound =
        PendingCredentialIssueTicketV1::read_from(&mut fixture.encoded_ticket.as_slice()).unwrap();
    assert!(
        authenticate_linux_writer_session(
            &fixture.attestation_bytes,
            fixture.publication_key,
            &fixture.channel,
            RETAINED_HANDOFF,
            LIVE_START,
            LIVE_IMAGE,
            RELEASE_TUPLE,
            fixture.channel.clone(),
            unbound,
            control,
            "/writer".into(),
            "/reader".into(),
        )
        .is_err()
    );
}
