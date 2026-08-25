use super::super::{CredentialBindingDigest, CredentialEnrollmentError};

macro_rules! measured_source {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $name(CredentialBindingDigest);

        impl $name {
            /// Captures a non-zero digest from this exact independent source.
            pub fn from_measured(bytes: [u8; 32]) -> Result<Self, CredentialEnrollmentError> {
                Ok(Self(CredentialBindingDigest::from_measured(bytes)?))
            }

            /// Returns the canonical stored binding digest.
            pub const fn digest(self) -> CredentialBindingDigest {
                self.0
            }
        }
    };
}

measured_source!(
    CandidateSourceIdentity,
    "Measured candidate source identity."
);
measured_source!(ReleaseManifestDigest, "Measured release manifest digest.");
measured_source!(
    DesktopExecutableIdentity,
    "Measured desktop executable identity."
);
measured_source!(
    WriterExecutableIdentity,
    "Measured writer executable identity."
);
measured_source!(
    ReaderExecutableIdentity,
    "Measured reader executable identity."
);
measured_source!(ContractBundleDigest, "Measured contract bundle digest.");
measured_source!(DaemonAuthorityId, "Measured daemon authority identity.");
measured_source!(ProtectedSessionId, "Measured protected-session identity.");
measured_source!(WriterLaunchId, "Measured writer launch identity.");
measured_source!(
    WriterProcessStartIdentity,
    "OS-native writer process start identity."
);
measured_source!(
    WriterProcessHandleIdentity,
    "Retained writer process handle identity."
);
measured_source!(
    BrokerChannelBinding,
    "Measured inherited broker channel binding."
);
measured_source!(
    ContinuationBindingDigest,
    "Accepted continuation authority digest."
);

/// Independently measured live writer process identity; paths and PIDs are absent.
///
/// ```compile_fail
/// use runne_provider::{CredentialProcessBinding, WriterProcessHandleIdentity, WriterProcessStartIdentity};
/// let start = WriterProcessStartIdentity::from_measured([1; 32]).unwrap();
/// let handle = WriterProcessHandleIdentity::from_measured([2; 32]).unwrap();
/// let _ = CredentialProcessBinding::new(handle, start);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredentialProcessBinding {
    start_identity: WriterProcessStartIdentity,
    retained_handle_identity: WriterProcessHandleIdentity,
}

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
    pub const fn start_identity(self) -> CredentialBindingDigest {
        self.start_identity.digest()
    }

    /// Returns the retained-handle binding digest.
    pub const fn retained_handle_digest(self) -> CredentialBindingDigest {
        self.retained_handle_identity.digest()
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
    writer_launch_id: WriterLaunchId,
    writer_process_start_identity: WriterProcessStartIdentity,
    writer_process_handle_identity: WriterProcessHandleIdentity,
    broker_channel_binding: BrokerChannelBinding,
    continuation_binding_digest: ContinuationBindingDigest,
}

impl CredentialMeasurementSnapshot {
    /// Validates that no independent source aliases another source digest.
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
        writer_launch_id: WriterLaunchId,
        writer_process_start_identity: WriterProcessStartIdentity,
        writer_process_handle_identity: WriterProcessHandleIdentity,
        broker_channel_binding: BrokerChannelBinding,
        continuation_binding_digest: ContinuationBindingDigest,
    ) -> Result<Self, CredentialEnrollmentError> {
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
            writer_launch_id,
            writer_process_start_identity,
            writer_process_handle_identity,
            broker_channel_binding,
            continuation_binding_digest,
        })
    }

    /// Returns the source-typed live process binding.
    pub const fn process_binding(&self) -> CredentialProcessBinding {
        CredentialProcessBinding::new(
            self.writer_process_start_identity,
            self.writer_process_handle_identity,
        )
    }

    pub(super) const fn digests(&self) -> [CredentialBindingDigest; 13] {
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
}
