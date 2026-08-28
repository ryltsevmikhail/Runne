use std::sync::Arc;

use super::super::{CredentialBindingDigest, CredentialEnrollmentError};
use crate::credential::enrollment::authority::EnrollmentAuthoritySeal;

mod source;

pub use source::*;

/// Store-issued expected metadata for one installation readback.
pub struct ExpectedInstallMeasurement {
    digest: CredentialBindingDigest,
    seal: Arc<EnrollmentAuthoritySeal>,
}

impl ExpectedInstallMeasurement {
    pub(crate) fn issue(
        seal: Arc<EnrollmentAuthoritySeal>,
        bytes: [u8; 32],
    ) -> Result<Self, CredentialEnrollmentError> {
        Ok(Self {
            digest: CredentialBindingDigest::from_measured(bytes)?,
            seal,
        })
    }

    /// Returns metadata-only expected installation identity.
    pub const fn digest(&self) -> CredentialBindingDigest {
        self.digest
    }

    pub(crate) fn belongs_to(&self, seal: &Arc<EnrollmentAuthoritySeal>) -> bool {
        Arc::ptr_eq(&self.seal, seal)
    }
}

/// Reader-issued observed metadata for one installation readback.
pub struct ObservedInstallMeasurement {
    digest: CredentialBindingDigest,
    seal: Arc<EnrollmentAuthoritySeal>,
}

impl ObservedInstallMeasurement {
    pub(crate) fn issue(
        seal: Arc<EnrollmentAuthoritySeal>,
        bytes: [u8; 32],
    ) -> Result<Self, CredentialEnrollmentError> {
        Ok(Self {
            digest: CredentialBindingDigest::from_measured(bytes)?,
            seal,
        })
    }

    /// Returns metadata-only observed installation identity.
    pub const fn digest(&self) -> CredentialBindingDigest {
        self.digest
    }

    pub(crate) fn belongs_to(&self, seal: &Arc<EnrollmentAuthoritySeal>) -> bool {
        Arc::ptr_eq(&self.seal, seal)
    }
}
/// Independently measured live writer process identity; paths and PIDs are absent.
///
/// ```compile_fail
/// use runne_provider::{CredentialProcessBinding, WriterProcessHandleIdentity, WriterProcessStartIdentity};
/// let start = WriterProcessStartIdentity::from_measured([1; 32]).unwrap();
/// let handle = WriterProcessHandleIdentity::from_measured([2; 32]).unwrap();
/// let _ = CredentialProcessBinding::new(handle, start);
/// ```
#[derive(Clone, Debug)]
pub struct CredentialProcessBinding {
    start_identity: WriterProcessStartIdentity,
    retained_handle_identity: WriterProcessHandleIdentity,
}

impl PartialEq for CredentialProcessBinding {
    fn eq(&self, other: &Self) -> bool {
        self.start_identity.digest() == other.start_identity.digest()
            && self.retained_handle_identity.digest() == other.retained_handle_identity.digest()
    }
}

impl Eq for CredentialProcessBinding {}

impl CredentialProcessBinding {
    /// Combines source-specific start and retained-handle measurements.
    pub const fn new(
        start_identity: WriterProcessStartIdentity,
        retained_handle_identity: WriterProcessHandleIdentity,
    ) -> Self {
        Self {
            start_identity,
            retained_handle_identity,
        }
    }

    /// Returns the process-start binding digest.
    pub const fn start_identity(&self) -> CredentialBindingDigest {
        self.start_identity.digest()
    }

    /// Returns the retained-handle binding digest.
    pub const fn retained_handle_digest(&self) -> CredentialBindingDigest {
        self.retained_handle_identity.digest()
    }

    pub(crate) fn belongs_to(&self, seal: &Arc<EnrollmentAuthoritySeal>) -> bool {
        self.start_identity.belongs_to(seal) && self.retained_handle_identity.belongs_to(seal)
    }
}

/// Validated, source-separated measurements for one exact live writer claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialMeasurementSnapshot {
    candidate_source_identity: CandidateSourceIdentity,
    release_manifest_digest: ReleaseManifestDigest,
    desktop_executable_identity: DesktopExecutableIdentity,
    writer_executable_identity: WriterExecutableIdentity,
    reader_executable_identity: ReaderExecutableIdentity,
    contract_bundle_digest: ContractBundleDigest,
    daemon_authority_id: DaemonAuthorityId,
    protected_session_id: ProtectedSessionId,
    desktop_supervisor_generation: DesktopSupervisorGeneration,
    writer_launch_id: WriterLaunchId,
    writer_process_start_identity: WriterProcessStartIdentity,
    writer_process_handle_identity: WriterProcessHandleIdentity,
    broker_channel_binding: BrokerChannelBinding,
    continuation_binding_digest: ContinuationBindingDigest,
}

impl CredentialMeasurementSnapshot {
    /// Validates one authority source and distinct digests for every measurement.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        candidate_source_identity: CandidateSourceIdentity,
        release_manifest_digest: ReleaseManifestDigest,
        desktop_executable_identity: DesktopExecutableIdentity,
        writer_executable_identity: WriterExecutableIdentity,
        reader_executable_identity: ReaderExecutableIdentity,
        contract_bundle_digest: ContractBundleDigest,
        daemon_authority_id: DaemonAuthorityId,
        protected_session_id: ProtectedSessionId,
        desktop_supervisor_generation: DesktopSupervisorGeneration,
        writer_launch_id: WriterLaunchId,
        writer_process_start_identity: WriterProcessStartIdentity,
        writer_process_handle_identity: WriterProcessHandleIdentity,
        broker_channel_binding: BrokerChannelBinding,
        continuation_binding_digest: ContinuationBindingDigest,
    ) -> Result<Self, CredentialEnrollmentError> {
        let seal = candidate_source_identity.authority_seal();
        if !release_manifest_digest.belongs_to(seal)
            || !desktop_executable_identity.belongs_to(seal)
            || !writer_executable_identity.belongs_to(seal)
            || !reader_executable_identity.belongs_to(seal)
            || !contract_bundle_digest.belongs_to(seal)
            || !daemon_authority_id.belongs_to(seal)
            || !protected_session_id.belongs_to(seal)
            || !desktop_supervisor_generation.belongs_to(seal)
            || !writer_launch_id.belongs_to(seal)
            || !writer_process_start_identity.belongs_to(seal)
            || !writer_process_handle_identity.belongs_to(seal)
            || !broker_channel_binding.belongs_to(seal)
            || !continuation_binding_digest.belongs_to(seal)
        {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        let digests = [
            candidate_source_identity.digest(),
            release_manifest_digest.digest(),
            desktop_executable_identity.digest(),
            writer_executable_identity.digest(),
            reader_executable_identity.digest(),
            contract_bundle_digest.digest(),
            daemon_authority_id.digest(),
            protected_session_id.digest(),
            writer_launch_id.digest(),
            writer_process_start_identity.digest(),
            writer_process_handle_identity.digest(),
            broker_channel_binding.digest(),
            continuation_binding_digest.digest(),
        ];
        for (index, digest) in digests.iter().enumerate() {
            if digests[index + 1..].contains(digest) {
                return Err(CredentialEnrollmentError::InvalidInput);
            }
        }
        Ok(Self {
            candidate_source_identity,
            release_manifest_digest,
            desktop_executable_identity,
            writer_executable_identity,
            reader_executable_identity,
            contract_bundle_digest,
            daemon_authority_id,
            protected_session_id,
            desktop_supervisor_generation,
            writer_launch_id,
            writer_process_start_identity,
            writer_process_handle_identity,
            broker_channel_binding,
            continuation_binding_digest,
        })
    }

    /// Returns the source-typed live process binding.
    pub fn process_binding(&self) -> CredentialProcessBinding {
        CredentialProcessBinding::new(
            self.writer_process_start_identity.clone(),
            self.writer_process_handle_identity.clone(),
        )
    }

    pub(super) fn digests(&self) -> [CredentialBindingDigest; 13] {
        [
            self.candidate_source_identity.digest(),
            self.release_manifest_digest.digest(),
            self.desktop_executable_identity.digest(),
            self.writer_executable_identity.digest(),
            self.reader_executable_identity.digest(),
            self.contract_bundle_digest.digest(),
            self.daemon_authority_id.digest(),
            self.protected_session_id.digest(),
            self.writer_launch_id.digest(),
            self.writer_process_start_identity.digest(),
            self.writer_process_handle_identity.digest(),
            self.broker_channel_binding.digest(),
            self.continuation_binding_digest.digest(),
        ]
    }

    pub(super) const fn desktop_supervisor_generation(&self) -> u64 {
        self.desktop_supervisor_generation.generation()
    }

    /// Returns the immutable continuation digest bound to this measurement snapshot.
    pub const fn continuation_binding_digest(&self) -> CredentialBindingDigest {
        self.continuation_binding_digest.digest()
    }

    /// Returns the exact measured broker-channel binding digest.
    pub const fn broker_channel_binding_digest(&self) -> CredentialBindingDigest {
        self.broker_channel_binding.digest()
    }

    pub(crate) fn belongs_to(&self, seal: &Arc<EnrollmentAuthoritySeal>) -> bool {
        self.candidate_source_identity.belongs_to(seal)
    }
}
