use std::sync::Arc;

use super::{
    BrokerChannelBinding, CandidateSourceIdentity, ContinuationBindingDigest, ContractBundleDigest,
    CredentialEnrollmentError, CredentialMeasurementSnapshot, CredentialOperationAction,
    CredentialOperationState, CredentialTransitionEvidence, DaemonAuthorityId,
    DesktopExecutableIdentity, ExpectedInstallMeasurement, ObservedInstallMeasurement,
    ProtectedSessionId, ReaderExecutableIdentity, ReleaseManifestDigest, TransitionCommand,
    WriterExecutableIdentity, WriterLaunchId, WriterProcessHandleIdentity,
    WriterProcessStartIdentity,
};

#[derive(Debug)]
pub(crate) struct EnrollmentAuthoritySeal;

/// Issues the paired store and measurement authorities for one enrollment domain.
pub struct CredentialEnrollmentAuthorityPair {
    store: CredentialEnrollmentStoreAuthority,
    measurements: CredentialEnrollmentMeasurementAuthority,
}

impl CredentialEnrollmentAuthorityPair {
    /// Creates one isolated authority pair.
    pub fn new() -> Self {
        let seal = Arc::new(EnrollmentAuthoritySeal);
        Self {
            store: CredentialEnrollmentStoreAuthority { seal: seal.clone() },
            measurements: CredentialEnrollmentMeasurementAuthority { seal },
        }
    }

    /// Separates the store issuer from the independent measurement issuer.
    pub fn split(
        self,
    ) -> (
        CredentialEnrollmentStoreAuthority,
        CredentialEnrollmentMeasurementAuthority,
    ) {
        (self.store, self.measurements)
    }
}

impl Default for CredentialEnrollmentAuthorityPair {
    fn default() -> Self {
        Self::new()
    }
}

/// Store-side authority that exclusively issues enrollment transition commands.
pub struct CredentialEnrollmentStoreAuthority {
    seal: Arc<EnrollmentAuthoritySeal>,
}

impl CredentialEnrollmentStoreAuthority {
    /// Issues a transition after validating its structural and evidence guards.
    pub fn issue_transition_command(
        &self,
        action: CredentialOperationAction,
        from: CredentialOperationState,
        to: CredentialOperationState,
        evidence: CredentialTransitionEvidence,
    ) -> Result<TransitionCommand, CredentialEnrollmentError> {
        TransitionCommand::issue(self.seal.clone(), action, from, to, evidence)
    }

    /// Rejects a command issued by a different enrollment authority pair.
    pub fn validate_transition_command(
        &self,
        command: &TransitionCommand,
    ) -> Result<(), CredentialEnrollmentError> {
        if command.belongs_to(&self.seal) {
            Ok(())
        } else {
            Err(CredentialEnrollmentError::InvalidEvidence)
        }
    }

    /// Rejects a measurement snapshot issued by another authority pair.
    pub fn validate_measurement_snapshot(
        &self,
        snapshot: &CredentialMeasurementSnapshot,
    ) -> Result<(), CredentialEnrollmentError> {
        if snapshot.belongs_to(&self.seal) {
            Ok(())
        } else {
            Err(CredentialEnrollmentError::InvalidEvidence)
        }
    }

    /// Issues expected metadata for a store-owned installation readback.
    pub fn expected_install_measurement(
        &self,
        bytes: [u8; 32],
    ) -> Result<ExpectedInstallMeasurement, CredentialEnrollmentError> {
        ExpectedInstallMeasurement::issue(self.seal.clone(), bytes)
    }

    /// Confirms a reader observation against this store authority's expectation.
    pub fn matches_expected_install(
        &self,
        expected: &ExpectedInstallMeasurement,
        observed: &ObservedInstallMeasurement,
    ) -> Result<bool, CredentialEnrollmentError> {
        if !expected.belongs_to(&self.seal) || !observed.belongs_to(&self.seal) {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        Ok(expected.digest() == observed.digest())
    }
}

/// Independent issuer for observed installation and source measurements.
pub struct CredentialEnrollmentMeasurementAuthority {
    seal: Arc<EnrollmentAuthoritySeal>,
}

impl CredentialEnrollmentMeasurementAuthority {
    /// Issues the independently observed metadata-only installation measurement.
    pub fn observed_install_measurement(
        &self,
        bytes: [u8; 32],
    ) -> Result<ObservedInstallMeasurement, CredentialEnrollmentError> {
        ObservedInstallMeasurement::issue(self.seal.clone(), bytes)
    }
}

macro_rules! issue_measurement {
    ($method:ident, $measurement:ident) => {
        impl CredentialEnrollmentMeasurementAuthority {
            /// Issues source-typed metadata without exposing a raw wrapper constructor.
            pub fn $method(
                &self,
                bytes: [u8; 32],
            ) -> Result<$measurement, CredentialEnrollmentError> {
                $measurement::issue(self.seal.clone(), bytes)
            }
        }
    };
}

issue_measurement!(candidate_source_identity, CandidateSourceIdentity);
issue_measurement!(release_manifest_digest, ReleaseManifestDigest);
issue_measurement!(desktop_executable_identity, DesktopExecutableIdentity);
issue_measurement!(writer_executable_identity, WriterExecutableIdentity);
issue_measurement!(reader_executable_identity, ReaderExecutableIdentity);
issue_measurement!(contract_bundle_digest, ContractBundleDigest);
issue_measurement!(daemon_authority_id, DaemonAuthorityId);
issue_measurement!(protected_session_id, ProtectedSessionId);
issue_measurement!(writer_launch_id, WriterLaunchId);
issue_measurement!(writer_process_start_identity, WriterProcessStartIdentity);
issue_measurement!(writer_process_handle_identity, WriterProcessHandleIdentity);
issue_measurement!(broker_channel_binding, BrokerChannelBinding);
issue_measurement!(continuation_binding_digest, ContinuationBindingDigest);
