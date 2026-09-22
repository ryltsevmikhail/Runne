//! Platform-neutral writer-session attestation claims builder (step 1 of
//! the accepted M6 resolution): both the macOS writer authority and the
//! Linux pidfd writer authority feed the SAME claim construction — only the
//! measured fact sources differ. Linux `release_tuple` is the approved local
//! content pin (activation-record binding), never a signer identity.

use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::{
    CredentialBindingDigest, CredentialBrokerFrame, CredentialInstallationOwnerId,
    CredentialIssueTicketBindingV1, CredentialWriterSessionAttestationClaimsV1,
    CredentialWriterSessionProcessClaimsV1, CredentialWriterSessionRuntimeClaimsV1,
    CredentialWriterSessionTicketClaimsV1, IssuedCredentialTicketAttempt,
};

pub(super) struct SessionClaimInputs {
    pub(super) owner: CredentialInstallationOwnerId,
    pub(super) begin_proof: CredentialBindingDigest,
    pub(super) protected_session: [u8; 32],
    pub(super) tauri_peer: [u8; 32],
    pub(super) daemon_authority: [u8; 32],
    pub(super) database_generation: u64,
    pub(super) supervisor_generation: u64,
    pub(super) release_tuple: CredentialBindingDigest,
    pub(super) endpoint_handoff_digest: [u8; 32],
    pub(super) writer_process_start: [u8; 32],
    pub(super) writer_image: [u8; 32],
    pub(super) writer_kill_public_key: [u8; 32],
}

pub(super) fn build_session_claims(
    receipt: &IssuedCredentialTicketAttempt,
    frame: &CredentialBrokerFrame,
    daemon_start: [u8; 32],
    daemon_image: [u8; 32],
    inputs: &SessionClaimInputs,
) -> Result<CredentialWriterSessionAttestationClaimsV1, ProviderCredentialEnrollmentHostError> {
    let issue = CredentialIssueTicketBindingV1::from_issue_ticket(frame)
        .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
    let CredentialBrokerFrame::IssueTicket { binding, .. } = frame else {
        return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
    };
    let digest = |value| {
        CredentialBindingDigest::from_measured(value)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)
    };
    Ok(CredentialWriterSessionAttestationClaimsV1::new(
        CredentialWriterSessionTicketClaimsV1::new(
            receipt.operation().operation_id(),
            receipt.ticket_attempt(),
            issue,
            *binding,
            inputs.owner,
            inputs.begin_proof,
            receipt.issued_at_high_water(),
            receipt.expires_at_high_water(),
        )
        .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?,
        CredentialWriterSessionRuntimeClaimsV1::new(
            digest(inputs.protected_session)?,
            digest(inputs.tauri_peer)?,
            digest(inputs.daemon_authority)?,
            inputs.database_generation,
            inputs.supervisor_generation,
            inputs.release_tuple,
        )
        .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?,
        CredentialWriterSessionProcessClaimsV1::new(
            digest(inputs.endpoint_handoff_digest)?,
            digest(inputs.writer_process_start)?,
            digest(inputs.writer_image)?,
            digest(inputs.writer_kill_public_key)?,
            digest(daemon_start)?,
            digest(daemon_image)?,
        )
        .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?,
    ))
}
