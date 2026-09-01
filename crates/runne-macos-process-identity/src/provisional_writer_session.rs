use runne_api::VerifiedSignedInstalledReleaseV2;
use runne_provider::{PendingCredentialIssueTicketV1, SignedCredentialWriterSessionAttestationV1};

use crate::packaged_writer_observation::{
    CapturedPackagedWriterObservationV1, package::PackagedWriterArtifacts,
};
use crate::signed_code_identity::match_retained_code_identities;
use crate::{MacOsPackagedWriterObservationError, MacOsUntrustedWriterEndpointHandoffV1};

#[doc(hidden)]
pub struct MacOsPendingProvisionalReleaseMatchV1 {
    handoff: MacOsUntrustedWriterEndpointHandoffV1,
    attestation: SignedCredentialWriterSessionAttestationV1,
    issue_ticket: PendingCredentialIssueTicketV1,
    observation: CapturedPackagedWriterObservationV1,
}

#[doc(hidden)]
pub struct MacOsPendingProvisionalWriterSessionV1 {
    #[allow(dead_code)]
    handoff: MacOsUntrustedWriterEndpointHandoffV1,
    #[allow(dead_code)]
    attestation: SignedCredentialWriterSessionAttestationV1,
    #[allow(dead_code)]
    issue_ticket: PendingCredentialIssueTicketV1,
    #[allow(dead_code)]
    release: VerifiedSignedInstalledReleaseV2,
    #[allow(dead_code)]
    observation: CapturedPackagedWriterObservationV1,
}

impl MacOsPendingProvisionalReleaseMatchV1 {
    pub(super) const fn from_bootstrap(
        handoff: MacOsUntrustedWriterEndpointHandoffV1,
        attestation: SignedCredentialWriterSessionAttestationV1,
        issue_ticket: PendingCredentialIssueTicketV1,
        observation: CapturedPackagedWriterObservationV1,
    ) -> Self {
        Self {
            handoff,
            attestation,
            issue_ticket,
            observation,
        }
    }

    /// Matches retained native facts to one exact signed installed release.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when any retained fact does not match.
    #[doc(hidden)]
    pub fn match_signed_release(
        self,
        release: VerifiedSignedInstalledReleaseV2,
    ) -> Result<MacOsPendingProvisionalWriterSessionV1, MacOsPackagedWriterObservationError> {
        let Self {
            handoff,
            attestation,
            issue_ticket,
            observation,
        } = self;
        matches_release_artifacts(&release, observation.package())
            .then_some(())
            .ok_or(MacOsPackagedWriterObservationError::Rejected)?;
        match_retained_code_identities(
            &release,
            observation.package(),
            observation.self_process(),
            observation.peer_process(),
        )?;
        matches_attested_facts(
            &attestation,
            &issue_ticket,
            &handoff,
            &observation,
            &release,
        )
        .then_some(())
        .ok_or(MacOsPackagedWriterObservationError::Rejected)?;

        observation.revalidate_for_provisional_session(&handoff)?;
        Ok(MacOsPendingProvisionalWriterSessionV1 {
            handoff,
            attestation,
            issue_ticket,
            release,
            observation,
        })
    }
}

fn matches_release_artifacts(
    release: &VerifiedSignedInstalledReleaseV2,
    package: &PackagedWriterArtifacts,
) -> bool {
    release.matches_desktop_digest(package.desktop_digest())
        && release.matches_writer_digest(package.writer_digest())
        && release.matches_daemon_digest(package.daemon_digest())
        && release.matches_contract_digest(package.contract_digest())
}

fn matches_attested_facts(
    attestation: &SignedCredentialWriterSessionAttestationV1,
    issue_ticket: &PendingCredentialIssueTicketV1,
    handoff: &MacOsUntrustedWriterEndpointHandoffV1,
    observation: &CapturedPackagedWriterObservationV1,
    release: &VerifiedSignedInstalledReleaseV2,
) -> bool {
    let writer_start = observation.self_process().start_digest();
    let daemon_start = observation.peer().process_start_digest();
    let release_binding = release.release_binding_matcher();
    attestation.matches_pending_issue_ticket(issue_ticket)
        && attestation.matches_handoff(
            handoff.observation_channel_binding(),
            handoff.observation_publication_public_key(),
            handoff.observation_handoff_digest(),
        )
        && attestation.matches_live_processes(
            &writer_start,
            observation.package().writer_digest(),
            &daemon_start,
            observation.package().daemon_digest(),
        )
        && attestation.matches_provisional_release_binding(&release_binding)
}
