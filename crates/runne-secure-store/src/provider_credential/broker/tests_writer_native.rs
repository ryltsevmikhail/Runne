#[cfg(unix)]
use std::path::PathBuf;
use std::sync::MutexGuard;
use std::sync::{Arc, Mutex};

use runne_provider::{
    BrokerChannelBinding, CredentialAuthorityPair, CredentialBindingDigest,
    CredentialBrokerCommand, CredentialBrokerFrame, CredentialFence, CredentialLifecycleRevision,
    CredentialNativeCreateClaim, CredentialOperationAction, CredentialOperationId,
    CredentialTicketAttempt, CredentialVersionRef, CredentialWriterAuthorityPair,
    NativeCredentialDeletionProof, ProviderId,
};

use super::super::migration::BrokeredCreateInput;
use super::super::writer::{
    BrokeredProviderCredentialWriter, BrokeredProviderCredentialWriterAdapter,
    NativeBrokeredProviderCredentialWriter,
};
use crate::{
    NativeProviderCredentialVersionStore, ProviderCredentialAccessPolicy, ProviderCredentialId,
    ProviderCredentialMaterial, ProviderCredentialSource, ProviderCredentialStatus,
    ProviderCredentialStore, SecureStoreError,
};

#[test]
fn native_writer_creates_only_the_exact_broker_version() {
    let observed = Arc::new(Mutex::new(None));
    let (lifecycle, _) = CredentialAuthorityPair::new().split();
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let command = create_command(7, 3);
    let binding = binding();
    let channel = channel();
    let authorization = authorization(&issuer, &command);
    let access = current_writer_access();
    let writer = BrokeredProviderCredentialWriterAdapter::new(
        effects,
        NativeBrokeredProviderCredentialWriter::new(lifecycle, RecordingNative(observed.clone())),
        access.policy.clone(),
    );
    let input = BrokeredCreateInput::new(command.clone(), binding, channel.clone()).unwrap();
    let sealed =
        runne_provider::sealed_pair_for_test(&command, binding, &channel, b"secret".to_vec())
            .unwrap();

    let result = writer.create_sealed_exact(authorization, input, sealed.pending, sealed.envelope);
    drop(access);
    result.unwrap();

    assert_eq!(
        observed.lock().unwrap().as_ref(),
        command.target().version_ref()
    );
}

#[test]
fn native_writer_rejects_a_non_writer_process_before_create() {
    let observed = Arc::new(Mutex::new(None));
    let (lifecycle, _) = CredentialAuthorityPair::new().split();
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let command = create_command(8, 4);
    let binding = binding();
    let channel = channel();
    let authorization = authorization(&issuer, &command);
    let writer = BrokeredProviderCredentialWriterAdapter::new(
        effects,
        NativeBrokeredProviderCredentialWriter::new(lifecycle, RecordingNative(observed.clone())),
        foreign_access(),
    );
    let sealed =
        runne_provider::sealed_pair_for_test(&command, binding, &channel, b"secret".to_vec())
            .unwrap();
    let input = BrokeredCreateInput::new(command, binding, channel).unwrap();

    assert_eq!(
        writer.create_sealed_exact(authorization, input, sealed.pending, sealed.envelope),
        Err(SecureStoreError::CredentialIdentityMismatch)
    );
    assert_eq!(*observed.lock().unwrap(), None);
}

struct RecordingNative(Arc<Mutex<Option<CredentialVersionRef>>>);

impl NativeProviderCredentialVersionStore for RecordingNative {
    fn version_status(
        &self,
        _reference: &CredentialVersionRef,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError> {
        unreachable!()
    }
    fn create_version(
        &self,
        claim: CredentialNativeCreateClaim,
        _credential: &ProviderCredentialMaterial,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        *self.0.lock().unwrap() = Some(claim.version_ref().clone());
        Ok(())
    }
    fn load_version(
        &self,
        _capability: &runne_provider::CredentialDispatchCapability,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        unreachable!()
    }
    fn delete_version(
        &self,
        _claim: runne_provider::CredentialGcClaim,
    ) -> Result<NativeCredentialDeletionProof, SecureStoreError> {
        unreachable!()
    }
}

impl ProviderCredentialStore for RecordingNative {
    fn provider_credential_status(
        &self,
        _provider: ProviderCredentialId,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialStatus, SecureStoreError> {
        unreachable!()
    }
    fn store_provider_credential(
        &self,
        _provider: ProviderCredentialId,
        _credential: &ProviderCredentialMaterial,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        unreachable!()
    }
    fn load_provider_credential(
        &self,
        _provider: ProviderCredentialId,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
        unreachable!()
    }
    fn load_provider_credential_source(
        &self,
        _provider: ProviderCredentialId,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialSource, SecureStoreError> {
        unreachable!()
    }
    fn delete_provider_credential(
        &self,
        _provider: ProviderCredentialId,
    ) -> Result<(), SecureStoreError> {
        unreachable!()
    }
    fn migrate_provider_credential_access(
        &self,
        _provider: ProviderCredentialId,
        _current: &ProviderCredentialAccessPolicy,
        _replacement: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        unreachable!()
    }
}

fn authorization(
    issuer: &runne_provider::CredentialWriterClaimIssuer,
    command: &CredentialBrokerCommand,
) -> runne_provider::ClaimedWriterAuthorization {
    let binding = binding();
    let channel = channel();
    let pending = issuer.issue_pending_claim(command, binding, &channel);
    issuer
        .claim_accepted(
            pending,
            CredentialBrokerFrame::ClaimAccepted {
                operation_id: command.operation_id(),
                attempt: command.ticket_attempt(),
            },
            command,
            binding,
            &channel,
        )
        .unwrap()
}

fn create_command(operation: u8, version: u64) -> CredentialBrokerCommand {
    let provider = ProviderId::new("openai").unwrap();
    CredentialBrokerCommand::new(
        CredentialOperationId::from_bytes([operation; 16]).unwrap(),
        CredentialTicketAttempt::new(1).unwrap(),
        provider.clone(),
        CredentialOperationAction::Pair,
        runne_provider::CredentialBrokerTarget::Version(
            CredentialVersionRef::new(provider, version).unwrap(),
        ),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        None,
    )
    .unwrap()
}

fn binding() -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([9; 32]).unwrap()
}
fn channel() -> BrokerChannelBinding {
    let (_, measurements) = runne_provider::CredentialEnrollmentAuthorityPair::new().split();
    measurements.broker_channel_binding([8; 32]).unwrap()
}
struct CurrentWriterAccess {
    policy: ProviderCredentialAccessPolicy,
    #[cfg(unix)]
    path: PathBuf,
    _lock: MutexGuard<'static, ()>,
    #[cfg(unix)]
    original_mode: u32,
}

impl Drop for CurrentWriterAccess {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(
                &self.path,
                std::fs::Permissions::from_mode(self.original_mode),
            );
        }
    }
}

fn current_writer_access() -> CurrentWriterAccess {
    let lock = crate::provider_credential::EXECUTABLE_TEST_LOCK
        .lock()
        .unwrap();
    let path = std::env::current_exe().unwrap();
    #[cfg(unix)]
    let original_mode = {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500)).unwrap();
        mode
    };
    let policy = ProviderCredentialAccessPolicy::new(&path, &path).unwrap();
    CurrentWriterAccess {
        policy,
        #[cfg(unix)]
        path,
        _lock: lock,
        #[cfg(unix)]
        original_mode,
    }
}

fn foreign_access() -> ProviderCredentialAccessPolicy {
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
