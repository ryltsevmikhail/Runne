#[cfg(all(test, unix))]
use runne_provider::daemon_credential_publication::{
    CredentialSecretPublicationSigner, CredentialWriterSessionAttestationSigner,
};
use runne_provider::{
    CredentialBindingDigest, CredentialBrokerFrame, CredentialEnrollmentError,
    CredentialInstallationOwnerId, CredentialIssueTicketBindingV1,
    CredentialWriterSessionAttestationClaimsV1, CredentialWriterSessionProcessClaimsV1,
    CredentialWriterSessionRuntimeClaimsV1, CredentialWriterSessionTicketClaimsV1,
};

#[cfg(all(test, unix))]
pub(crate) fn attest_publication_signer(
    signer: CredentialWriterSessionAttestationSigner,
    frame: &CredentialBrokerFrame,
) -> Result<CredentialSecretPublicationSigner, CredentialEnrollmentError> {
    signer
        .sign(writer_session_claims(frame)?)
        .map(|(_, publication)| publication)
}

pub(crate) fn writer_session_claims(
    frame: &CredentialBrokerFrame,
) -> Result<CredentialWriterSessionAttestationClaimsV1, CredentialEnrollmentError> {
    let issue_ticket = CredentialIssueTicketBindingV1::from_issue_ticket(frame)?;
    let CredentialBrokerFrame::IssueTicket {
        operation_id,
        attempt,
        binding,
        ..
    } = frame
    else {
        return Err(CredentialEnrollmentError::InvalidFrame);
    };
    Ok(CredentialWriterSessionAttestationClaimsV1::new(
        CredentialWriterSessionTicketClaimsV1::new(
            *operation_id,
            *attempt,
            issue_ticket,
            *binding,
            CredentialInstallationOwnerId::from_bytes([2; 32])?,
            digest(3)?,
            1,
            2,
        )?,
        CredentialWriterSessionRuntimeClaimsV1::new(
            digest(4)?,
            digest(5)?,
            digest(6)?,
            1,
            1,
            digest(7)?,
        )?,
        CredentialWriterSessionProcessClaimsV1::new(
            digest(8)?,
            digest(9)?,
            digest(10)?,
            digest(11)?,
            digest(12)?,
            digest(13)?,
        )?,
    ))
}

fn digest(value: u8) -> Result<CredentialBindingDigest, CredentialEnrollmentError> {
    CredentialBindingDigest::from_measured([value; 32])
}
