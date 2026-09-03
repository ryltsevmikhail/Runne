#[cfg(unix)]
use std::path::PathBuf;
use std::sync::{
    Arc, MutexGuard,
    atomic::{AtomicUsize, Ordering},
};

use runne_provider::{
    BrokerChannelBinding, CredentialBindingDigest, CredentialBrokerCommand, CredentialBrokerFrame,
    CredentialBrokerTarget, CredentialEnrollmentAuthorityPair, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationAction, CredentialOperationId,
    CredentialTicketAttempt, CredentialVersionRef, CredentialWriterAuthorityPair, ProviderId,
};

use super::super::{BrokeredLegacySourceDeleteInput, BrokeredMigrateLegacyInput};
use super::legacy_source::{
    BrokeredProviderCredentialLegacySource, NativeProviderCredentialLegacySource,
};
use crate::{
    ProviderCredentialAccessPolicy, ProviderCredentialId, ProviderCredentialMaterial,
    ProviderCredentialSource, ProviderCredentialSourceRevision, ProviderCredentialStatus,
    ProviderCredentialStore, SecureStoreError,
};

#[test]
fn exact_legacy_migration_loads_the_source_once_into_service_material() {
    let access = current_writer_access();
    let loads = Arc::new(AtomicUsize::new(0));
    let source = NativeProviderCredentialLegacySource::new(
        RecordingLegacyStore::new(loads.clone(), Arc::new(AtomicUsize::new(0))),
        access.policy.clone(),
    );
    let input = BrokeredMigrateLegacyInput::new(
        command(CredentialOperationAction::MigrateLegacy),
        binding(9),
        channel(),
    )
    .unwrap();

    let material = source.load_exact(&input).unwrap();
    drop(access);

    material.consume(|bytes| assert_eq!(bytes, b"legacy-secret"));
    assert_eq!(loads.load(Ordering::SeqCst), 1);
}

#[test]
fn legacy_cleanup_requires_exact_claim_before_deleting_the_source() {
    let access = current_writer_access();
    let deletes = Arc::new(AtomicUsize::new(0));
    let source = NativeProviderCredentialLegacySource::new(
        RecordingLegacyStore::new(Arc::new(AtomicUsize::new(0)), deletes.clone()),
        access.policy.clone(),
    );
    let command = command(CredentialOperationAction::LegacySourceCleanup);
    let channel = channel();
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let authorization = authorization(&issuer, &command, binding(9), &channel);
    let input = BrokeredLegacySourceDeleteInput::new(command, binding(10), channel).unwrap();

    assert_eq!(
        source.delete_exact(&effects, authorization, input),
        Err(SecureStoreError::CredentialAccessDenied)
    );
    drop(access);
    assert_eq!(deletes.load(Ordering::SeqCst), 0);
}

#[test]
fn exact_legacy_cleanup_deletes_the_source_once() {
    let access = current_writer_access();
    let deletes = Arc::new(AtomicUsize::new(0));
    let source = NativeProviderCredentialLegacySource::new(
        RecordingLegacyStore::new(Arc::new(AtomicUsize::new(0)), deletes.clone()),
        access.policy.clone(),
    );
    let command = command(CredentialOperationAction::LegacySourceCleanup);
    let channel = channel();
    let binding = binding(9);
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let authorization = authorization(&issuer, &command, binding, &channel);
    let input = BrokeredLegacySourceDeleteInput::new(command, binding, channel).unwrap();

    source.delete_exact(&effects, authorization, input).unwrap();
    drop(access);

    assert_eq!(deletes.load(Ordering::SeqCst), 1);
}

struct RecordingLegacyStore {
    loads: Arc<AtomicUsize>,
    deletes: Arc<AtomicUsize>,
}

impl RecordingLegacyStore {
    const fn new(loads: Arc<AtomicUsize>, deletes: Arc<AtomicUsize>) -> Self {
        Self { loads, deletes }
    }
}

impl ProviderCredentialStore for RecordingLegacyStore {
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
        provider: ProviderCredentialId,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialSource, SecureStoreError> {
        assert_eq!(provider, ProviderCredentialId::OpenAi);
        self.loads.fetch_add(1, Ordering::SeqCst);
        Ok(ProviderCredentialSource::new(
            ProviderCredentialMaterial::new(b"legacy-secret".to_vec()).unwrap(),
            ProviderCredentialSourceRevision::new([7; 16]).unwrap(),
        ))
    }

    fn delete_provider_credential(
        &self,
        provider: ProviderCredentialId,
    ) -> Result<(), SecureStoreError> {
        assert_eq!(provider, ProviderCredentialId::OpenAi);
        self.deletes.fetch_add(1, Ordering::SeqCst);
        Ok(())
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

fn command(action: CredentialOperationAction) -> CredentialBrokerCommand {
    let provider = ProviderId::new("openai").unwrap();
    let target = match action {
        CredentialOperationAction::MigrateLegacy => CredentialBrokerTarget::LegacyImport(
            CredentialVersionRef::new(provider.clone(), 1).unwrap(),
        ),
        CredentialOperationAction::LegacySourceCleanup => CredentialBrokerTarget::LegacySource,
        _ => unreachable!(),
    };
    CredentialBrokerCommand::new(
        CredentialOperationId::from_bytes([3; 16]).unwrap(),
        CredentialTicketAttempt::new(1).unwrap(),
        provider,
        action,
        target,
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        None,
    )
    .unwrap()
}

fn authorization(
    issuer: &runne_provider::CredentialWriterClaimIssuer,
    command: &CredentialBrokerCommand,
    binding: CredentialBindingDigest,
    channel: &BrokerChannelBinding,
) -> runne_provider::ClaimedWriterAuthorization {
    let pending = issuer.issue_pending_claim(command, binding, channel);
    issuer
        .claim_accepted(
            pending,
            CredentialBrokerFrame::ClaimAccepted {
                operation_id: command.operation_id(),
                attempt: command.ticket_attempt(),
            },
            command,
            binding,
            channel,
        )
        .unwrap()
}

fn binding(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}

fn channel() -> BrokerChannelBinding {
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
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
