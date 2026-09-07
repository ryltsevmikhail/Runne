mod deadline;
mod qualified;

use std::time::Duration;

use runne_api::PendingSignedInstalledReleaseMetadataV2;
use runne_provider::{
    CredentialWriterSessionAttestationCodec, PendingCredentialIssueTicketV1,
    SignedCredentialWriterSessionAttestationV1, SignedCredentialWriterSessionAttestationV2,
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

pub enum BootstrapAttestation {
    V1(SignedCredentialWriterSessionAttestationV1),
    Qualified(SignedCredentialWriterSessionAttestationV2),
}

enum BootstrapPrefixVersion {
    V1(BootstrapPrefix),
    Qualified {
        attestation: SignedCredentialWriterSessionAttestationV2,
        issue_ticket: PendingCredentialIssueTicketV1,
        release: PendingSignedInstalledReleaseMetadataV2,
    },
}

#[doc(hidden)]
pub struct MacOsPendingWriterBootstrapTranscriptV1 {
    handoff: MacOsUntrustedWriterEndpointHandoffV1,
    attestation: BootstrapAttestation,
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

    /// Observes either the unchanged V1 or the qualification-required V2
    /// bootstrap, selected by the attestation version byte.
    #[doc(hidden)]
    pub fn observe_pending_writer_bootstrap_any(
        self,
    ) -> Result<MacOsPendingWriterBootstrapTranscriptV1, MacOsPackagedWriterObservationError> {
        qualified::observe_any(self, &PrefixBudget::Production)
    }

    /// Observes only the qualification-required V2 bootstrap.
    #[doc(hidden)]
    pub fn observe_pending_qualified_writer_bootstrap(
        self,
    ) -> Result<MacOsPendingWriterBootstrapTranscriptV1, MacOsPackagedWriterObservationError> {
        let transcript = qualified::observe_any(self, &PrefixBudget::Production)?;
        if transcript.is_qualified() {
            Ok(transcript)
        } else {
            Err(MacOsPackagedWriterObservationError::Rejected)
        }
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
    pub const fn is_qualified(&self) -> bool {
        matches!(self.attestation, BootstrapAttestation::Qualified(_))
    }

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
        attestation: BootstrapAttestation::V1(prefix.attestation),
        issue_ticket: prefix.issue_ticket,
        release: prefix.release,
        observation,
    })
}

impl PrefixBudget {
    #[cfg(feature = "test-support")]
    fn duration(&self) -> Duration {
        match self {
            Self::Production => production_or_local_prefix_budget(),
            #[cfg(test)]
            Self::Test(duration) => *duration,
        }
    }

    #[cfg(not(feature = "test-support"))]
    const fn duration(&self) -> Duration {
        match self {
            Self::Production => production_or_local_prefix_budget(),
            #[cfg(test)]
            Self::Test(duration) => *duration,
        }
    }
}

#[cfg(feature = "test-support")]
fn production_or_local_prefix_budget() -> Duration {
    let opted_in = std::env::var_os("RUNNE_LOCAL_NATIVE_ENROLLMENT_TEST").as_deref()
        == Some(std::ffi::OsStr::new("1"));
    prefix_budget_for_local_test_opt_in(opted_in)
}

#[cfg(any(test, feature = "test-support"))]
const fn prefix_budget_for_local_test_opt_in(opted_in: bool) -> Duration {
    if opted_in {
        Duration::from_mins(2)
    } else {
        PRODUCTION_PREFIX_BUDGET
    }
}

#[cfg(not(feature = "test-support"))]
const fn production_or_local_prefix_budget() -> Duration {
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
