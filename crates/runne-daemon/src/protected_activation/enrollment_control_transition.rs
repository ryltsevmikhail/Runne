#![cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    allow(unused_imports, dead_code)
)]
//! Same-process V2→V3 enrollment transition composition on the entered channel.

use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use runne_api::{
    LaunchAuthorityError, ProtectedActivationKeys, ProtectedCredentialEnrollmentOwnedLaunchV3,
    ProtectedCredentialEnrollmentPrepareV2, ProtectedLaunchRequestV2,
    ProviderActivationReadinessV1,
};
use runne_application::local_session::LocalSessionService;

use super::ProtectedActivationChannel;
use crate::application::provider_credential_enrollment::broker::rendezvous::{
    DaemonBrokerAuthority, DaemonOwnedUnixBrokerRendezvous,
};

mod fanout;

pub(crate) type EnrollmentTicketClock =
    Arc<dyn Fn() -> Result<u64, LaunchAuthorityError> + Send + Sync>;

/// Immutable daemon composition facts for one enrollment transition.
pub(crate) struct EnrollmentControlComposition {
    pub(super) original_request: ProtectedLaunchRequestV2,
    pub(super) installation_identity_digest: [u8; 32],
    pub(super) provider_readiness: ProviderActivationReadinessV1,
    pub(super) endpoint: String,
    pub(super) certificate_sha256: [u8; 32],
    pub(super) certificate_der: Vec<u8>,
    pub(super) capabilities: Vec<String>,
    pub(super) profile_directory: PathBuf,
    pub(super) runtime_root: PathBuf,
    pub(super) ticket_clock: EnrollmentTicketClock,
    pub(super) enrollment_control: Option<Arc<
        crate::application::provider_credential_enrollment::DaemonProviderCredentialEnrollmentControl,
    >>,
    pub(super) enrollment_controls: Vec<(
        String,
        Arc<crate::application::provider_credential_enrollment::DaemonProviderCredentialEnrollmentControl>,
    )>,
}

#[allow(clippy::too_many_arguments)]
impl EnrollmentControlComposition {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        original_request: ProtectedLaunchRequestV2,
        installation_identity_digest: [u8; 32],
        provider_readiness: ProviderActivationReadinessV1,
        endpoint: String,
        certificate_sha256: [u8; 32],
        certificate_der: Vec<u8>,
        capabilities: Vec<String>,
        profile_directory: PathBuf,
        runtime_root: PathBuf,
        ticket_clock: EnrollmentTicketClock,
        enrollment_control: Option<Arc<
            crate::application::provider_credential_enrollment::DaemonProviderCredentialEnrollmentControl,
        >>,
    ) -> Self {
        Self {
            original_request,
            installation_identity_digest,
            provider_readiness,
            endpoint,
            certificate_sha256,
            certificate_der,
            capabilities,
            profile_directory,
            runtime_root,
            ticket_clock,
            enrollment_control,
            enrollment_controls: Vec::new(),
        }
    }

    pub(crate) fn ticket_clock(&self) -> EnrollmentTicketClock {
        Arc::clone(&self.ticket_clock)
    }
}

/// Daemon-retained halves of one enrollment rendezvous, consumed exactly once
/// by the authenticated writer handoff mounted in the V3 control loop.
pub(crate) struct DaemonEnrollmentRendezvous {
    owned: Option<DaemonOwnedUnixBrokerRendezvous>,
    authority: Option<DaemonBrokerAuthority>,
    writer_endpoint: Option<UnixStream>,
}

impl DaemonEnrollmentRendezvous {
    pub(super) fn new(owned: DaemonOwnedUnixBrokerRendezvous) -> Self {
        Self {
            owned: Some(owned),
            authority: None,
            writer_endpoint: None,
        }
    }

    pub(crate) fn into_owned(
        mut self,
    ) -> Result<DaemonOwnedUnixBrokerRendezvous, LaunchAuthorityError> {
        self.owned
            .take()
            .ok_or(LaunchAuthorityError::OwnershipMismatch)
    }

    pub(crate) fn prepare_dispatch(&mut self) -> Result<(), LaunchAuthorityError> {
        let mut owned = self
            .owned
            .take()
            .ok_or(LaunchAuthorityError::OwnershipMismatch)?;
        self.authority = Some(
            owned
                .take_daemon_authority()
                .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?,
        );
        self.writer_endpoint = Some(
            owned
                .take_writer_endpoint()
                .map_err(|_| LaunchAuthorityError::OwnershipMismatch)?,
        );
        Ok(())
    }

    /// Returns the inert channel binding before or after dispatch preparation.
    pub(crate) fn channel_binding(&self) -> Result<[u8; 32], LaunchAuthorityError> {
        self.owned
            .as_ref()
            .map(DaemonOwnedUnixBrokerRendezvous::channel_binding)
            .or_else(|| {
                self.authority
                    .as_ref()
                    .map(DaemonBrokerAuthority::channel_binding)
            })
            .ok_or(LaunchAuthorityError::OwnershipMismatch)
    }

    /// Returns the inert publication key before or after dispatch preparation.
    pub(crate) fn publication_public_key(&self) -> Result<[u8; 32], LaunchAuthorityError> {
        self.owned
            .as_ref()
            .map(DaemonOwnedUnixBrokerRendezvous::publication_public_key)
            .or_else(|| {
                self.authority
                    .as_ref()
                    .map(DaemonBrokerAuthority::publication_public_key)
            })
            .ok_or(LaunchAuthorityError::OwnershipMismatch)
    }

    /// Daemon half of the rendezvous, used for the exact writer peer capture.
    pub(crate) fn broker_authority(&self) -> &DaemonBrokerAuthority {
        self.authority
            .as_ref()
            .expect("dispatch preparation installs daemon authority")
    }

    /// Moves the writer endpoint into the authenticated descriptor transfer once.
    pub(crate) fn take_writer_endpoint(&mut self) -> Option<UnixStream> {
        self.writer_endpoint.take()
    }

    /// Creates a fresh production rendezvous for loop-level fixtures.
    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self::new(DaemonOwnedUnixBrokerRendezvous::create().unwrap())
    }
}

/// Everything the caller needs to enter the V3 control loop.
pub(crate) struct EnrollmentTransitionOutcome {
    keys: ProtectedActivationKeys,
    owned_launch: ProtectedCredentialEnrollmentOwnedLaunchV3,
    rendezvous: DaemonEnrollmentRendezvous,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    installed_facts: Option<runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts>,
    #[cfg(target_os = "linux")]
    linux_writer_capability: Option<runne_platform_desktop::VerifiedInstalledLinuxWriterCapability>,
}

impl EnrollmentTransitionOutcome {
    #[cfg(target_os = "linux")]
    pub(super) fn owned_launch(&self) -> &ProtectedCredentialEnrollmentOwnedLaunchV3 {
        &self.owned_launch
    }

    pub(super) fn new(
        keys: ProtectedActivationKeys,
        owned_launch: ProtectedCredentialEnrollmentOwnedLaunchV3,
        rendezvous: DaemonEnrollmentRendezvous,
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))] installed_facts: Option<
            runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts,
        >,
    ) -> Self {
        Self {
            keys,
            owned_launch,
            rendezvous,
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            installed_facts,
            #[cfg(target_os = "linux")]
            linux_writer_capability: None,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn with_linux_writer_capability(
        mut self,
        capability: runne_platform_desktop::VerifiedInstalledLinuxWriterCapability,
    ) -> Self {
        self.linux_writer_capability = Some(capability);
        self
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn take_linux_writer_capability(
        &mut self,
    ) -> Option<runne_platform_desktop::VerifiedInstalledLinuxWriterCapability> {
        self.linux_writer_capability.take()
    }

    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn into_parts(
        self,
    ) -> (
        ProtectedActivationKeys,
        ProtectedCredentialEnrollmentOwnedLaunchV3,
        DaemonEnrollmentRendezvous,
        Option<runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts>,
    ) {
        (
            self.keys,
            self.owned_launch,
            self.rendezvous,
            self.installed_facts,
        )
    }

    /// Off macOS the V3 loop enters without installed measurement facts.
    #[cfg(all(unix, not(all(target_os = "macos", target_arch = "aarch64"))))]
    pub(crate) fn into_parts_unix(
        self,
    ) -> (
        ProtectedActivationKeys,
        ProtectedCredentialEnrollmentOwnedLaunchV3,
        DaemonEnrollmentRendezvous,
    ) {
        (self.keys, self.owned_launch, self.rendezvous)
    }
}

/// Platform composition of the production exchange lives in its own module.
pub(super) use super::enrollment_exchange_platform::run_enrollment_control_exchange;
