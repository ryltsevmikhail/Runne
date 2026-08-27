use std::sync::Arc;

use super::{
    BrokerChannelBinding, CandidateSourceIdentity, ContinuationBindingDigest, ContractBundleDigest,
    CredentialBindingDigest, CredentialEnrollmentError, CredentialMeasurementSnapshot,
    CredentialMigrationMetadata, CredentialOperationAction, CredentialOperationState,
    CredentialProcessBinding, CredentialQualifiedReleaseTuple, CredentialReleaseMigrationBinding,
    CredentialTransitionEvidence, CredentialVerificationCapability, CredentialVerificationLease,
    DaemonAuthorityId, DesktopExecutableIdentity, ExpectedInstallMeasurement,
    ObservedInstallMeasurement, ProtectedSessionId, ReaderExecutableIdentity,
    ReleaseManifestDigest, TransitionCommand, WriterExecutableIdentity, WriterLaunchId,
    WriterProcessHandleIdentity, WriterProcessStartIdentity,
};

pub(crate) mod claim;
mod migration_metadata;
mod ticket;
pub mod writer;

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

    /// Issues a verification lease after the Task 3 store has accepted its persistence CAS.
    ///
    /// This provider-only authority seals the lease but cannot prove persistence ordering; Task 3
    /// owns that cross-crate invariant and must call this only after successful acceptance.
    pub fn issue_credential_verification_lease(
        &self,
        begin: super::BeginCredentialVerification,
        active_credential_version: crate::CredentialVersionRef,
    ) -> CredentialVerificationLease {
        CredentialVerificationLease::issue(self.seal.clone(), begin, active_credential_version)
    }

    /// Rejects a capability not sealed by this store/measurement authority pair.
    pub fn validate_credential_verification_capability(
        &self,
        capability: &CredentialVerificationCapability,
    ) -> Result<(), CredentialEnrollmentError> {
        if capability.belongs_to(&self.seal) {
            Ok(())
        } else {
            Err(CredentialEnrollmentError::InvalidEvidence)
        }
    }

    /// Materializes sealed migration metadata only from this pair's measured migration binding.
    ///
    /// ```compile_fail
    /// use runne_provider::{
    ///     CredentialBindingDigest, CredentialEnrollmentStoreAuthority,
    ///     CredentialReleaseMigrationBinding,
    /// };
    ///
    /// fn cannot_substitute_tuple_digests(
    ///     store: &CredentialEnrollmentStoreAuthority,
    ///     binding: &CredentialReleaseMigrationBinding,
    ///     digest: CredentialBindingDigest,
    /// ) {
    ///     let _ = store.issue_credential_migration_metadata(binding, digest, digest);
    /// }
    /// ```
    pub fn issue_credential_migration_metadata(
        &self,
        binding: &CredentialReleaseMigrationBinding,
    ) -> Result<CredentialMigrationMetadata, CredentialEnrollmentError> {
        if !binding.belongs_to(&self.seal) {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        Ok(CredentialMigrationMetadata::issue(
            self.seal.clone(),
            binding.migration_id(),
            binding.phase(),
            binding.old_tuple_digest(),
            binding.new_tuple_digest(),
            binding.digest(),
        ))
    }

    /// Rejects migration metadata materialized by a different authority pair.
    pub fn validate_credential_migration_metadata(
        &self,
        metadata: &CredentialMigrationMetadata,
    ) -> Result<(), CredentialEnrollmentError> {
        if metadata.belongs_to(&self.seal) {
            Ok(())
        } else {
            Err(CredentialEnrollmentError::InvalidEvidence)
        }
    }
}

/// Independent issuer for observed installation and source measurements.
#[derive(Clone)]
pub struct CredentialEnrollmentMeasurementAuthority {
    seal: Arc<EnrollmentAuthoritySeal>,
}

impl CredentialEnrollmentMeasurementAuthority {
    /// Seals one already-qualified release manifest for durable enrollment binding.
    pub fn issue_qualified_credential_release_tuple(
        &self,
        release_manifest: ReleaseManifestDigest,
    ) -> Result<CredentialQualifiedReleaseTuple, CredentialEnrollmentError> {
        if !release_manifest.belongs_to(&self.seal) {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        Ok(CredentialQualifiedReleaseTuple::issue(
            self.seal.clone(),
            release_manifest.digest(),
        ))
    }

    /// Issues the independently observed metadata-only installation measurement.
    pub fn observed_install_measurement(
        &self,
        bytes: [u8; 32],
    ) -> Result<ObservedInstallMeasurement, CredentialEnrollmentError> {
        ObservedInstallMeasurement::issue(self.seal.clone(), bytes)
    }

    /// Issues the independently observed desktop supervisor generation.
    pub fn desktop_supervisor_generation(
        &self,
        generation: u64,
    ) -> Result<super::DesktopSupervisorGeneration, CredentialEnrollmentError> {
        super::DesktopSupervisorGeneration::issue(self.seal.clone(), generation)
    }

    /// Binds a store lease to this process-local verifier digest under the shared authority seal.
    pub fn issue_credential_verification_capability(
        &self,
        lease: CredentialVerificationLease,
        binding_digest: CredentialBindingDigest,
    ) -> Result<CredentialVerificationCapability, CredentialEnrollmentError> {
        if !lease.belongs_to(&self.seal) {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        Ok(CredentialVerificationCapability::issue(
            self.seal.clone(),
            lease,
            binding_digest,
        ))
    }

    /// Issues one migration binding from same-pair, independently measured process evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_credential_release_migration_binding(
        &self,
        migration_id: super::CredentialOperationId,
        phase: super::WriterIdentityMigrationPhase,
        old_candidate_and_manifest: CredentialBindingDigest,
        new_candidate_and_manifest: CredentialBindingDigest,
        old_desktop_writer_reader_contract: CredentialBindingDigest,
        new_desktop_writer_reader_contract: CredentialBindingDigest,
        database_generation: u64,
        expected_lifecycle_revision: super::CredentialLifecycleRevision,
        expected_prior_fence: super::CredentialFence,
        live_process: CredentialProcessBinding,
    ) -> Result<CredentialReleaseMigrationBinding, CredentialEnrollmentError> {
        CredentialReleaseMigrationBinding::issue(
            self.seal.clone(),
            migration_id,
            phase,
            old_candidate_and_manifest,
            new_candidate_and_manifest,
            old_desktop_writer_reader_contract,
            new_desktop_writer_reader_contract,
            database_generation,
            expected_lifecycle_revision,
            expected_prior_fence,
            live_process,
        )
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
