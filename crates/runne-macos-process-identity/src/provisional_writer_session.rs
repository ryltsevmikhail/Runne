mod qualified;

use runne_api::{PendingSignedInstalledReleaseMetadataV2, VerifiedSignedInstalledReleaseV2};
use runne_provider::PendingCredentialIssueTicketV1;
use std::path::PathBuf;

use crate::packaged_writer_observation::{
    CapturedPackagedWriterObservationV1, package::PackagedWriterArtifacts,
};
use crate::signed_code_identity::match_retained_code_identities;
use crate::writer_bootstrap_transcript::BootstrapAttestation;
use crate::{MacOsPackagedWriterObservationError, MacOsUntrustedWriterEndpointHandoffV1};

/// Opaque provisional release match with no ordinary constructor or conversion.
///
/// ```compile_fail
/// fn require_clone<T: Clone>() {}
/// require_clone::<runne_macos_process_identity::MacOsPendingProvisionalReleaseMatchV1>();
/// ```
///
/// ```compile_fail
/// fn convert(
///     value: runne_macos_process_identity::MacOsPendingPackagedWriterObservationV1,
/// ) -> runne_macos_process_identity::MacOsPendingProvisionalReleaseMatchV1 {
///     value.into()
/// }
/// ```
#[doc(hidden)]
pub struct MacOsPendingProvisionalReleaseMatchV1 {
    handoff: MacOsUntrustedWriterEndpointHandoffV1,
    attestation: BootstrapAttestation,
    issue_ticket: PendingCredentialIssueTicketV1,
    observation: CapturedPackagedWriterObservationV1,
}

/// Opaque provisional session that exposes neither facts nor authority.
///
/// ```compile_fail
/// fn require_default<T: Default>() {}
/// require_default::<runne_macos_process_identity::MacOsPendingProvisionalWriterSessionV1>();
/// ```
///
/// ```compile_fail
/// fn raw_release(
///     value: &runne_macos_process_identity::MacOsPendingProvisionalWriterSessionV1,
/// ) {
///     let _ = value.release();
/// }
/// ```
///
/// ```compile_fail
/// fn mint(
///     value: runne_macos_process_identity::MacOsPendingProvisionalWriterSessionV1,
/// ) {
///     let _ = value.mint();
/// }
/// ```
#[doc(hidden)]
pub struct MacOsPendingProvisionalWriterSessionV1 {
    #[allow(dead_code)]
    handoff: MacOsUntrustedWriterEndpointHandoffV1,
    #[allow(dead_code)]
    attestation: BootstrapAttestation,
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
        attestation: BootstrapAttestation,
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

    /// Verifies pinned metadata and matches every retained native fact.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when any retained fact does not match.
    #[doc(hidden)]
    pub fn match_current_pinned_release(
        self,
        metadata: PendingSignedInstalledReleaseMetadataV2,
    ) -> Result<MacOsPendingProvisionalWriterSessionV1, MacOsPackagedWriterObservationError> {
        let expectation = match &self.attestation {
            BootstrapAttestation::V1(attestation) => attestation.release_binding_expectation(),
            BootstrapAttestation::Qualified(attestation) => {
                attestation.release_binding_expectation()
            }
        };
        let release = metadata
            .verify_current_pinned(expectation)
            .map_err(|_| MacOsPackagedWriterObservationError::Rejected)?;
        qualified::attestation_is_current(&self.attestation)
            .then_some(())
            .ok_or(MacOsPackagedWriterObservationError::Rejected)?;
        self.match_verified_current_release(release)
    }

    fn match_verified_current_release(
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
        qualified::matches_attested_facts(&attestation, &issue_ticket, &handoff, &observation)
            .then_some(())
            .ok_or(MacOsPackagedWriterObservationError::Rejected)?;

        qualified::attestation_is_current(&attestation)
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

    /// Exercises native matching with a synthetic exact release in integration tests.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn test_only_match_verified_release(
        self,
        release: VerifiedSignedInstalledReleaseV2,
    ) -> Result<MacOsPendingProvisionalWriterSessionV1, MacOsPackagedWriterObservationError> {
        self.match_verified_current_release(release)
    }

    #[cfg(test)]
    pub(crate) fn test_only_revalidate_after_final_race(
        mut self,
        race: crate::packaged_writer_observation::FinalRaceDrift,
    ) -> Result<(), MacOsPackagedWriterObservationError> {
        self.observation.test_only_inject_final_race(race);
        self.observation
            .revalidate_for_provisional_session(&self.handoff)
    }
}

impl MacOsPendingProvisionalWriterSessionV1 {
    fn reauthenticate_current(self) -> Result<Self, MacOsPackagedWriterObservationError> {
        matches_release_artifacts(&self.release, self.observation.package())
            .then_some(())
            .ok_or(MacOsPackagedWriterObservationError::Rejected)?;
        match_retained_code_identities(
            &self.release,
            self.observation.package(),
            self.observation.self_process(),
            self.observation.peer_process(),
        )?;
        qualified::matches_attested_facts(
            &self.attestation,
            &self.issue_ticket,
            &self.handoff,
            &self.observation,
        )
        .then_some(())
        .ok_or(MacOsPackagedWriterObservationError::Rejected)?;
        qualified::attestation_is_current(&self.attestation)
            .then_some(())
            .ok_or(MacOsPackagedWriterObservationError::Rejected)?;
        self.observation
            .revalidate_for_provisional_session(&self.handoff)?;
        Ok(self)
    }

    /// Revalidates and consumes every retained native resource exactly once.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when any fact drifted before extraction.
    #[doc(hidden)]
    #[allow(
        clippy::type_complexity,
        reason = "the authority layer immediately wraps all five resources"
    )]
    pub fn into_authenticated_parts(
        self,
    ) -> Result<
        (
            std::os::unix::net::UnixStream,
            [u8; 32],
            PendingCredentialIssueTicketV1,
            PathBuf,
            PathBuf,
            VerifiedSignedInstalledReleaseV2,
        ),
        MacOsPackagedWriterObservationError,
    > {
        let verified = self.reauthenticate_current()?;
        let attestation = match verified.attestation {
            BootstrapAttestation::V1(_) => None,
            BootstrapAttestation::Qualified(attestation) => Some(attestation),
        };
        let issue_ticket = match attestation {
            Some(attestation) => verified
                .issue_ticket
                .with_qualified_attestation(attestation),
            None => verified.issue_ticket,
        };
        let writer = verified
            .observation
            .self_process()
            .native_code()
            .main_executable()
            .to_path_buf();
        let reader = verified
            .observation
            .peer_process()
            .native_code()
            .main_executable()
            .to_path_buf();
        let (control, channel) = verified.handoff.into_authenticated_control();
        Ok((
            std::os::unix::net::UnixStream::from(control),
            channel,
            issue_ticket,
            writer,
            reader,
            verified.release,
        ))
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
