use runne_provider::{
    CredentialBindingDigest, CredentialBrokerFrame, CredentialInstallationOwnerId,
    CredentialWriterSessionAttestationClaimsV1, CredentialWriterSessionProcessClaimsV1,
    CredentialWriterSessionRuntimeClaimsV1, CredentialWriterSessionTicketClaimsV1,
    IssuedCredentialTicketAttempt,
};

pub(super) fn claims(
    frame: &CredentialBrokerFrame,
    receipt: &IssuedCredentialTicketAttempt,
) -> CredentialWriterSessionAttestationClaimsV1 {
    let issue = runne_provider::CredentialIssueTicketBindingV1::from_issue_ticket(frame).unwrap();
    let CredentialBrokerFrame::IssueTicket {
        operation_id,
        attempt,
        binding,
        ..
    } = frame
    else {
        unreachable!()
    };
    let digest = |value| CredentialBindingDigest::from_measured([value; 32]).unwrap();
    CredentialWriterSessionAttestationClaimsV1::new(
        CredentialWriterSessionTicketClaimsV1::new(
            *operation_id,
            *attempt,
            issue,
            *binding,
            CredentialInstallationOwnerId::from_bytes([5; 32]).unwrap(),
            digest(6),
            receipt.issued_at_high_water(),
            receipt.expires_at_high_water(),
        )
        .unwrap(),
        CredentialWriterSessionRuntimeClaimsV1::new(
            digest(7),
            digest(8),
            digest(9),
            10,
            11,
            digest(12),
        )
        .unwrap(),
        CredentialWriterSessionProcessClaimsV1::new(
            digest(16),
            digest(17),
            digest(18),
            digest(19),
            digest(20),
            digest(21),
        )
        .unwrap(),
    )
}
