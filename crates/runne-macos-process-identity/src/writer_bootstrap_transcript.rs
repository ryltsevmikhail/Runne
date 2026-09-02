mod deadline;

use std::time::Duration;

use runne_api::PendingSignedInstalledReleaseMetadataV2;
use runne_provider::{
    CredentialWriterSessionAttestationCodec, PendingCredentialIssueTicketV1,
    SignedCredentialWriterSessionAttestationV1,
};

use self::deadline::DeadlineReader;
use crate::packaged_writer_observation::{CapturedPackagedWriterObservationV1, map_peer_error};
use crate::provisional_writer_session::MacOsPendingProvisionalReleaseMatchV1;
use crate::{
    MacOsLocalPeerProcessIdentity, MacOsPackagedWriterObservationError,
    MacOsUntrustedWriterEndpointHandoffV1,
};

const PRODUCTION_PREFIX_BUDGET: Duration = Duration::from_secs(1);

enum PrefixBudget {
    Production,
    #[cfg(test)]
    Test(Duration),
}

struct BootstrapPrefix {
    attestation: SignedCredentialWriterSessionAttestationV1,
    issue_ticket: PendingCredentialIssueTicketV1,
    release: PendingSignedInstalledReleaseMetadataV2,
}

#[doc(hidden)]
pub struct MacOsPendingWriterBootstrapTranscriptV1 {
    handoff: MacOsUntrustedWriterEndpointHandoffV1,
    attestation: SignedCredentialWriterSessionAttestationV1,
    issue_ticket: PendingCredentialIssueTicketV1,
    release: PendingSignedInstalledReleaseMetadataV2,
    observation: CapturedPackagedWriterObservationV1,
}

impl MacOsUntrustedWriterEndpointHandoffV1 {
    #[doc(hidden)]
    pub fn observe_pending_writer_bootstrap(
        self,
    ) -> Result<MacOsPendingWriterBootstrapTranscriptV1, MacOsPackagedWriterObservationError> {
        observe(self, &PrefixBudget::Production)
    }

    #[cfg(test)]
    pub(crate) fn test_only_observe_pending_writer_bootstrap(
        self,
        budget: Duration,
    ) -> Result<MacOsPendingWriterBootstrapTranscriptV1, MacOsPackagedWriterObservationError> {
        observe(self, &PrefixBudget::Test(budget))
    }
}

impl MacOsPendingWriterBootstrapTranscriptV1 {
    #[doc(hidden)]
    #[must_use]
    pub fn into_release_verification(
        self,
    ) -> (
        MacOsPendingProvisionalReleaseMatchV1,
        PendingSignedInstalledReleaseMetadataV2,
    ) {
        (
            MacOsPendingProvisionalReleaseMatchV1::from_bootstrap(
                self.handoff,
                self.attestation,
                self.issue_ticket,
                self.observation,
            ),
            self.release,
        )
    }
}

fn observe(
    handoff: MacOsUntrustedWriterEndpointHandoffV1,
    budget: &PrefixBudget,
) -> Result<MacOsPendingWriterBootstrapTranscriptV1, MacOsPackagedWriterObservationError> {
    let expected_public_key = *handoff.observation_publication_public_key();
    let peer = MacOsLocalPeerProcessIdentity::capture(handoff.observation_control())
        .map_err(map_peer_error)?;
    let prefix = {
        let mut reader = DeadlineReader::new(handoff.observation_control(), budget.duration())
            .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?;
        let prefix = read_prefix(&mut reader, expected_public_key)?;
        reader
            .reject_queued_input()
            .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?;
        prefix
    };
    let observation =
        CapturedPackagedWriterObservationV1::capture_with_retained_peer(&handoff, peer)?;
    Ok(MacOsPendingWriterBootstrapTranscriptV1 {
        handoff,
        attestation: prefix.attestation,
        issue_ticket: prefix.issue_ticket,
        release: prefix.release,
        observation,
    })
}

impl PrefixBudget {
    fn duration(&self) -> Duration {
        match self {
            Self::Production => production_or_local_prefix_budget(),
            #[cfg(test)]
            Self::Test(duration) => *duration,
        }
    }
}

fn production_or_local_prefix_budget() -> Duration {
    #[cfg(feature = "test-support")]
    if runne_api::test_support::validated_local_native_enrollment_case_name().is_some() {
        return Duration::from_mins(2);
    }
    PRODUCTION_PREFIX_BUDGET
}

fn read_prefix<R: std::io::Read>(
    reader: &mut R,
    expected_public_key: [u8; 32],
) -> Result<BootstrapPrefix, MacOsPackagedWriterObservationError> {
    let attestation =
        CredentialWriterSessionAttestationCodec::read_from(reader, expected_public_key)
            .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?;
    let issue_ticket = PendingCredentialIssueTicketV1::read_from(reader)
        .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?;
    let release = PendingSignedInstalledReleaseMetadataV2::read_from(reader)
        .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?;
    Ok(BootstrapPrefix {
        attestation,
        issue_ticket,
        release,
    })
}

#[cfg(test)]
#[path = "writer_bootstrap_transcript_tests.rs"]
mod tests;
