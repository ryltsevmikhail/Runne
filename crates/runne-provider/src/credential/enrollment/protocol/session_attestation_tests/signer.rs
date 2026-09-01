use crate::{
    BrokerChannelBinding, CredentialEnrollmentAuthorityPair, CredentialInstallationOwnerId,
    CredentialIssueTicketBindingV1, CredentialOperationId, CredentialSecretClaimOffer,
    CredentialTicketAttempt, CredentialWriterSessionTicketClaimsV1, daemon_credential_publication,
};

use super::support::{claims, command, digest, frame};

#[test]
fn publication_signer_accepts_only_attested_operation_attempt_claim_and_channel() {
    let exact_command = command(40, 1, 1);
    let claim = digest(41);
    let (exact_offer, _) = CredentialSecretClaimOffer::prepare(&exact_command, claim).unwrap();
    let exact_channel = channel([42; 32]);

    assert!(sign_publication(exact_offer, exact_channel.digest()).is_ok());

    for (command, claim, channel) in [
        (command(43, 1, 1), claim, exact_channel.digest()),
        (command(40, 2, 1), claim, exact_channel.digest()),
        (exact_command.clone(), digest(44), exact_channel.digest()),
        (exact_command, claim, channel([45; 32]).digest()),
    ] {
        let (offer, _) = CredentialSecretClaimOffer::prepare(&command, claim).unwrap();
        assert!(sign_publication(offer, channel).is_err());
    }
}

#[test]
fn ticket_claims_reject_issue_ticket_operation_substitution() {
    let actual = frame(40, 1, 46, 42, 41, 1);
    assert!(ticket_claims(&actual, 43, 1, 41).is_err());
}

#[test]
fn ticket_claims_reject_issue_ticket_attempt_substitution() {
    let actual = frame(40, 1, 46, 42, 41, 1);
    assert!(ticket_claims(&actual, 40, 2, 41).is_err());
}

#[test]
fn ticket_claims_reject_issue_ticket_claim_substitution() {
    let actual = frame(40, 1, 46, 42, 41, 1);
    assert!(ticket_claims(&actual, 40, 1, 44).is_err());
}

#[test]
fn ticket_claims_reject_lifetime_over_one_hour() {
    assert!(ticket_claims_with_lifetime(&frame(40, 1, 46, 42, 41, 1), 13, 3_613).is_ok());
    assert!(ticket_claims_with_lifetime(&frame(40, 1, 46, 42, 41, 1), 13, 3_614).is_err());
    assert!(
        ticket_claims_with_lifetime(&frame(40, 1, 46, 42, 41, 1), i64::MAX - 3_600, i64::MAX,)
            .is_ok()
    );
    assert!(
        ticket_claims_with_lifetime(&frame(40, 1, 46, 42, 41, 1), i64::MAX - 3_601, i64::MAX,)
            .is_err()
    );
    assert!(
        ticket_claims_with_lifetime(&frame(40, 1, 46, 42, 41, 1), i64::MIN, i64::MAX,).is_err()
    );
    assert!(
        ticket_claims_with_lifetime(&frame(40, 1, 46, 42, 41, 1), i64::MAX, i64::MIN,).is_err()
    );
}

#[test]
fn attestation_signer_rejects_issue_ticket_channel_substitution() {
    let actual = frame(40, 1, 46, 42, 41, 1);
    let signer =
        daemon_credential_publication::CredentialWriterSessionAttestationSigner::generate([45; 32])
            .unwrap();

    assert!(signer.sign(claims(&actual)).is_err());
}

fn ticket_claims(
    actual: &crate::CredentialBrokerFrame,
    operation: u8,
    attempt: u64,
    claim: u8,
) -> Result<CredentialWriterSessionTicketClaimsV1, crate::CredentialEnrollmentError> {
    CredentialWriterSessionTicketClaimsV1::new(
        CredentialOperationId::from_bytes([operation; 16])?,
        CredentialTicketAttempt::new(attempt)?,
        CredentialIssueTicketBindingV1::from_issue_ticket(actual)?,
        digest(claim),
        CredentialInstallationOwnerId::from_bytes([5; 32])?,
        digest(6),
        13,
        14,
    )
}

fn ticket_claims_with_lifetime(
    actual: &crate::CredentialBrokerFrame,
    issued_at: i64,
    expires_at: i64,
) -> Result<CredentialWriterSessionTicketClaimsV1, crate::CredentialEnrollmentError> {
    CredentialWriterSessionTicketClaimsV1::new(
        CredentialOperationId::from_bytes([40; 16])?,
        CredentialTicketAttempt::new(1)?,
        CredentialIssueTicketBindingV1::from_issue_ticket(actual)?,
        digest(41),
        CredentialInstallationOwnerId::from_bytes([5; 32])?,
        digest(6),
        issued_at,
        expires_at,
    )
}

fn sign_publication(
    offer: CredentialSecretClaimOffer,
    channel: crate::CredentialBindingDigest,
) -> Result<crate::CredentialSecretPublication, crate::CredentialEnrollmentError> {
    let frame = frame(40, 1, 46, 42, 41, 1);
    let signer =
        daemon_credential_publication::CredentialWriterSessionAttestationSigner::generate([42; 32])
            .unwrap();
    signer.sign(claims(&frame)).unwrap().1.sign(offer, channel)
}

fn channel(bytes: [u8; 32]) -> BrokerChannelBinding {
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    measurements.broker_channel_binding(bytes).unwrap()
}
