use runne_provider::PendingCredentialIssueTicketV1;

use super::super::writer_bootstrap_transcript::BootstrapAttestation;
use crate::MacOsUntrustedWriterEndpointHandoffV1;
use crate::packaged_writer_observation::CapturedPackagedWriterObservationV1;

pub(super) fn matches_attested_facts(
    attestation: &BootstrapAttestation,
    issue_ticket: &PendingCredentialIssueTicketV1,
    handoff: &MacOsUntrustedWriterEndpointHandoffV1,
    observation: &CapturedPackagedWriterObservationV1,
) -> bool {
    let writer_start = observation.self_process().start_digest();
    let daemon_start = observation.peer().process_start_digest();
    match attestation {
        BootstrapAttestation::V1(attestation) => matches(
            attestation,
            issue_ticket,
            handoff,
            observation,
            &writer_start,
            &daemon_start,
        ),
        BootstrapAttestation::Qualified(attestation) => matches(
            attestation,
            issue_ticket,
            handoff,
            observation,
            &writer_start,
            &daemon_start,
        ),
    }
}

fn matches<T: CredentialWriterSessionAttestationMatcher>(
    attestation: &T,
    issue_ticket: &PendingCredentialIssueTicketV1,
    handoff: &MacOsUntrustedWriterEndpointHandoffV1,
    observation: &CapturedPackagedWriterObservationV1,
    writer_start: &[u8; 32],
    daemon_start: &[u8; 32],
) -> bool {
    attestation.matches_pending_issue_ticket(issue_ticket)
        && attestation.matches_handoff(
            handoff.observation_channel_binding(),
            handoff.observation_publication_public_key(),
            handoff.observation_handoff_digest(),
        )
        && attestation.matches_live_processes(
            writer_start,
            observation.package().writer_digest(),
            daemon_start,
            observation.package().daemon_digest(),
        )
}

trait CredentialWriterSessionAttestationMatcher {
    fn matches_pending_issue_ticket(&self, issue_ticket: &PendingCredentialIssueTicketV1) -> bool;
    fn matches_handoff(&self, channel: &[u8; 32], key: &[u8; 32], handoff: &[u8; 32]) -> bool;
    fn matches_live_processes(
        &self,
        writer_start: &[u8; 32],
        writer_code: &[u8; 32],
        daemon_start: &[u8; 32],
        daemon_code: &[u8; 32],
    ) -> bool;
}

impl CredentialWriterSessionAttestationMatcher
    for runne_provider::SignedCredentialWriterSessionAttestationV1
{
    fn matches_pending_issue_ticket(&self, issue_ticket: &PendingCredentialIssueTicketV1) -> bool {
        self.matches_pending_issue_ticket(issue_ticket)
    }

    fn matches_handoff(&self, channel: &[u8; 32], key: &[u8; 32], handoff: &[u8; 32]) -> bool {
        self.matches_handoff(channel, key, handoff)
    }

    fn matches_live_processes(
        &self,
        writer_start: &[u8; 32],
        writer_code: &[u8; 32],
        daemon_start: &[u8; 32],
        daemon_code: &[u8; 32],
    ) -> bool {
        self.matches_live_processes(writer_start, writer_code, daemon_start, daemon_code)
    }
}

impl CredentialWriterSessionAttestationMatcher
    for runne_provider::SignedCredentialWriterSessionAttestationV2
{
    fn matches_pending_issue_ticket(&self, issue_ticket: &PendingCredentialIssueTicketV1) -> bool {
        self.matches_pending_issue_ticket(issue_ticket)
    }

    fn matches_handoff(&self, channel: &[u8; 32], key: &[u8; 32], handoff: &[u8; 32]) -> bool {
        self.matches_handoff(channel, key, handoff)
    }

    fn matches_live_processes(
        &self,
        writer_start: &[u8; 32],
        writer_code: &[u8; 32],
        daemon_start: &[u8; 32],
        daemon_code: &[u8; 32],
    ) -> bool {
        self.matches_live_processes(writer_start, writer_code, daemon_start, daemon_code)
    }
}

pub(super) fn attestation_is_current(attestation: &BootstrapAttestation) -> bool {
    match attestation {
        BootstrapAttestation::V1(attestation) => attestation.is_current_now(),
        BootstrapAttestation::Qualified(attestation) => attestation.is_current_now(),
    }
}
