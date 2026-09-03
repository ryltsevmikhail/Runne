use runne_provider::{
    BeginCredentialVerification, CredentialBindingDigest, CredentialDispatchCapability,
    CredentialEnrollmentAuthorityPair, CredentialFence, CredentialGcClaim,
    CredentialLifecycleRevision, CredentialNativeCreateClaim, CredentialOperationId,
    CredentialReadinessRevision, CredentialVerificationKind, CredentialVerificationLease,
    CredentialVerificationResult, CredentialVerifierRevision, CredentialVersionRef,
    NativeCredentialDeletionProof, ProviderId,
};

use super::readback::{LegacyCredentialSourceReadback, VersionStoreReadback};
use super::verification_readback::VersionStoreVerificationReadback;
use super::{
    ExactAbsenceReadback, ExactVersionReadback, ProviderCredentialReadback,
    ProviderCredentialVerificationReadback,
};
use crate::{
    NativeProviderCredentialVersionStore, ProviderCredentialAccessPolicy,
    ProviderCredentialMaterial, ProviderCredentialStatus, SecureStoreError,
};

#[test]
fn brokered_provider_credential_readback_returns_only_metadata() {
    let reader = VersionStoreReadback::new(ConfiguredVersionStore([7; 16]), access());
    let observation = reader
        .readback_exact_version(ExactVersionReadback::new(command(1, 1)).unwrap())
        .unwrap();
    assert!(observation.present());
    assert_ne!(observation.binding().as_bytes(), [0; 32]);
}

#[test]
fn service_presence_uses_the_same_pair_and_absence_observation_contract() {
    let pair = ExactVersionReadback::new(command(1, 1))
        .unwrap()
        .observe_service_presence(true)
        .unwrap();
    let revoke = ExactAbsenceReadback::new(revoke_command(2, 1))
        .unwrap()
        .observe_service_presence(false)
        .unwrap();

    assert!(pair.present());
    assert!(!revoke.present());
    assert_ne!(pair.binding(), revoke.binding());
}

#[test]
fn legacy_import_readback_binds_the_retained_source_revision() {
    let first = VersionStoreReadback::new(ConfiguredVersionStore([7; 16]), access())
        .readback_exact_version(ExactVersionReadback::new(legacy_import_command(1, 1)).unwrap())
        .unwrap();
    let second = VersionStoreReadback::new(ConfiguredVersionStore([8; 16]), access())
        .readback_exact_version(ExactVersionReadback::new(legacy_import_command(1, 1)).unwrap())
        .unwrap();

    assert!(first.present());
    assert!(second.present());
    assert_ne!(first.binding(), second.binding());
}

#[test]
fn brokered_provider_credential_proves_legacy_source_absence() {
    let reader = VersionStoreReadback::new(ConfiguredVersionStore([7; 16]), access());
    let provider = ProviderId::new("openai").unwrap();
    let command = runne_provider::CredentialBrokerCommand::new(
        runne_provider::CredentialOperationId::from_bytes([7; 16]).unwrap(),
        runne_provider::CredentialTicketAttempt::new(1).unwrap(),
        provider,
        runne_provider::CredentialOperationAction::LegacySourceCleanup,
        runne_provider::CredentialBrokerTarget::LegacySource,
        runne_provider::CredentialLifecycleRevision::new(1).unwrap(),
        runne_provider::CredentialFence::new(1).unwrap(),
        None,
    )
    .unwrap();
    let observation = reader
        .readback_exact_absence(ExactAbsenceReadback::new(command).unwrap())
        .unwrap();
    assert!(!observation.present());
}

#[test]
fn local_verification_reads_only_the_store_issued_exact_version_metadata() {
    let reader = VersionStoreVerificationReadback::new(ConfiguredVersionStore([7; 16]), access());

    assert_eq!(
        reader.verify_local(&local_verification_lease()).unwrap(),
        CredentialVerificationResult::Verified
    );
}

#[test]
fn local_verification_records_missing_exact_version_as_failed() {
    let reader = VersionStoreVerificationReadback::new(MissingVersionStore, access());

    assert_eq!(
        reader.verify_local(&local_verification_lease()).unwrap(),
        CredentialVerificationResult::Failed
    );
}

#[test]
fn runned_cannot_call_writer() {
    let daemon_manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates directory")
        .join("runne-daemon/Cargo.toml");
    let contents = std::fs::read_to_string(daemon_manifest).expect("runned manifest");
    assert!(
        !contents.contains("provider-credential-broker-writer"),
        "runned must not enable the writer-only secure-store feature"
    );
}

struct ConfiguredVersionStore([u8; 16]);

struct MissingVersionStore;

impl LegacyCredentialSourceReadback for ConfiguredVersionStore {
    fn legacy_source_status(
        &self,
        _provider: &ProviderId,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError> {
        Ok(ProviderCredentialStatus::Missing)
    }
}

impl NativeProviderCredentialVersionStore for ConfiguredVersionStore {
    fn version_status(
        &self,
        _reference: &CredentialVersionRef,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError> {
        Ok(ProviderCredentialStatus::Configured)
    }

    fn version_source_revision(
        &self,
        _reference: &CredentialVersionRef,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<crate::ProviderCredentialSourceRevision, SecureStoreError> {
        crate::ProviderCredentialSourceRevision::new(self.0)
    }

    fn create_version(
        &self,
        _claim: CredentialNativeCreateClaim,
        _credential: &ProviderCredentialMaterial,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        unreachable!()
    }

    fn load_version(
        &self,
        _capability: &CredentialDispatchCapability,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        unreachable!()
    }

    fn delete_version(
        &self,
        _claim: CredentialGcClaim,
    ) -> Result<NativeCredentialDeletionProof, SecureStoreError> {
        unreachable!()
    }
}

impl NativeProviderCredentialVersionStore for MissingVersionStore {
    fn version_status(
        &self,
        _reference: &CredentialVersionRef,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError> {
        Ok(ProviderCredentialStatus::Missing)
    }

    fn create_version(
        &self,
        _claim: CredentialNativeCreateClaim,
        _credential: &ProviderCredentialMaterial,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        unreachable!()
    }

    fn load_version(
        &self,
        _capability: &CredentialDispatchCapability,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        unreachable!()
    }

    fn delete_version(
        &self,
        _claim: CredentialGcClaim,
    ) -> Result<NativeCredentialDeletionProof, SecureStoreError> {
        unreachable!()
    }
}

fn access() -> ProviderCredentialAccessPolicy {
    let directory = tempfile::tempdir().unwrap();
    let executable = directory.path().join("runne");
    std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o500)).unwrap();
    }
    ProviderCredentialAccessPolicy::new(&executable, &executable).unwrap()
}

fn command(operation: u8, version: u64) -> runne_provider::CredentialBrokerCommand {
    let provider = ProviderId::new("openai").unwrap();
    runne_provider::CredentialBrokerCommand::new(
        runne_provider::CredentialOperationId::from_bytes([operation; 16]).unwrap(),
        runne_provider::CredentialTicketAttempt::new(1).unwrap(),
        provider.clone(),
        runne_provider::CredentialOperationAction::Pair,
        runne_provider::CredentialBrokerTarget::Version(
            CredentialVersionRef::new(provider, version).unwrap(),
        ),
        runne_provider::CredentialLifecycleRevision::new(1).unwrap(),
        runne_provider::CredentialFence::new(1).unwrap(),
        None,
    )
    .unwrap()
}

fn legacy_import_command(operation: u8, version: u64) -> runne_provider::CredentialBrokerCommand {
    let provider = ProviderId::new("openai").unwrap();
    runne_provider::CredentialBrokerCommand::new(
        runne_provider::CredentialOperationId::from_bytes([operation; 16]).unwrap(),
        runne_provider::CredentialTicketAttempt::new(1).unwrap(),
        provider.clone(),
        runne_provider::CredentialOperationAction::MigrateLegacy,
        runne_provider::CredentialBrokerTarget::LegacyImport(
            CredentialVersionRef::new(provider, version).unwrap(),
        ),
        runne_provider::CredentialLifecycleRevision::new(1).unwrap(),
        runne_provider::CredentialFence::new(1).unwrap(),
        None,
    )
    .unwrap()
}

fn revoke_command(operation: u8, version: u64) -> runne_provider::CredentialBrokerCommand {
    let provider = ProviderId::new("openai").unwrap();
    runne_provider::CredentialBrokerCommand::new(
        runne_provider::CredentialOperationId::from_bytes([operation; 16]).unwrap(),
        runne_provider::CredentialTicketAttempt::new(1).unwrap(),
        provider.clone(),
        runne_provider::CredentialOperationAction::Revoke,
        runne_provider::CredentialBrokerTarget::Version(
            CredentialVersionRef::new(provider, version).unwrap(),
        ),
        runne_provider::CredentialLifecycleRevision::new(1).unwrap(),
        runne_provider::CredentialFence::new(1).unwrap(),
        None,
    )
    .unwrap()
}

fn local_verification_lease() -> CredentialVerificationLease {
    let provider = ProviderId::new("openai").unwrap();
    let reference = CredentialVersionRef::new(provider.clone(), 1).unwrap();
    let begin = BeginCredentialVerification::new(
        CredentialOperationId::from_bytes([9; 16]).unwrap(),
        None,
        provider,
        CredentialVerificationKind::Local,
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        CredentialReadinessRevision::new(1).unwrap(),
        CredentialBindingDigest::from_measured([1; 32]).unwrap(),
        CredentialBindingDigest::from_measured([2; 32]).unwrap(),
        CredentialVerifierRevision::new(1).unwrap(),
        1,
        2,
    )
    .unwrap();
    let (store, _) = CredentialEnrollmentAuthorityPair::new().split();
    store.issue_credential_verification_lease(begin, reference)
}

#[cfg(feature = "provider-credential-broker-writer")]
#[path = "tests_writer.rs"]
mod writer;
#[cfg(feature = "provider-credential-broker-writer")]
#[path = "tests_writer_native.rs"]
mod writer_native;
