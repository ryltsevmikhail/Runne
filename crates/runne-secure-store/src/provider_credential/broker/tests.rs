use runne_provider::{
    CredentialDispatchCapability, CredentialGcClaim, CredentialNativeCreateClaim,
    CredentialVersionRef, NativeCredentialDeletionProof, ProviderId,
};

use super::readback::{LegacyCredentialSourceReadback, VersionStoreReadback};
use super::{ExactAbsenceReadback, ExactVersionReadback, ProviderCredentialReadback};
use crate::{
    NativeProviderCredentialVersionStore, ProviderCredentialAccessPolicy,
    ProviderCredentialMaterial, ProviderCredentialStatus, SecureStoreError,
};

#[test]
fn brokered_provider_credential_readback_returns_only_metadata() {
    let reader = VersionStoreReadback::new(ConfiguredVersionStore, access());
    let observation = reader
        .readback_exact_version(ExactVersionReadback::new(command(1, 1)).unwrap())
        .unwrap();
    assert!(observation.present());
    assert_ne!(observation.binding().as_bytes(), [0; 32]);
}

#[test]
fn brokered_provider_credential_proves_legacy_source_absence() {
    let reader = VersionStoreReadback::new(ConfiguredVersionStore, access());
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

struct ConfiguredVersionStore;

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

#[cfg(feature = "provider-credential-broker-writer")]
#[path = "tests_writer.rs"]
mod writer;
#[cfg(feature = "provider-credential-broker-writer")]
#[path = "tests_writer_native.rs"]
mod writer_native;
