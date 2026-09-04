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

use super::super::BrokeredLegacySourceDeleteInput;
use super::legacy_source::{
    BrokeredProviderCredentialLegacySource, NativeProviderCredentialLegacySource,
};
use crate::{
    ProviderCredentialAccessPolicy, ProviderCredentialId, ProviderCredentialMaterial,
    ProviderCredentialSource, ProviderCredentialSourceRevision, ProviderCredentialStatus,
    ProviderCredentialStore, SecureStoreError,
};

include!("legacy_read_fixture.inc");
include!("legacy_native_role_tests.inc");
#[path = "legacy_cleanup_tests.rs"]
mod cleanup;

#[test]
fn legacy_port_rejects_token_from_unretained_writer_authority() {
    let access = current_writer_access();
    let loads = Arc::new(AtomicUsize::new(0));
    let source = NativeProviderCredentialLegacySource::new(
        RecordingLegacyStore::new(loads.clone(), Arc::new(AtomicUsize::new(0))),
        access.policy.clone(),
        legacy_read_with_verifier().1,
    );
    assert_eq!(
        source.load_exact(authorized_legacy_read()).err(),
        Some(SecureStoreError::CredentialAccessDenied)
    );
    assert_eq!(loads.load(Ordering::SeqCst), 0);
    drop(access);
}

#[test]
fn exact_legacy_migration_loads_the_source_once_into_service_material() {
    let (read, verifier) = legacy_read_with_verifier();
    let access = current_writer_access();
    let loads = Arc::new(AtomicUsize::new(0));
    let source = NativeProviderCredentialLegacySource::new(
        RecordingLegacyStore::new(loads.clone(), Arc::new(AtomicUsize::new(0))),
        access.policy.clone(),
        verifier,
    );
    let material = source.load_exact(read).unwrap();
    drop(access);

    assert_eq!(material.source_revision(), [7; 16]);
    material
        .into_parts()
        .0
        .consume(|bytes| assert_eq!(bytes, b"legacy-secret"));
    assert_eq!(loads.load(Ordering::SeqCst), 1);
}

#[test]
fn legacy_cleanup_requires_exact_claim_before_deleting_the_source() {
    let access = current_writer_access();
    let deletes = Arc::new(AtomicUsize::new(0));
    let source = NativeProviderCredentialLegacySource::new(
        RecordingLegacyStore::new(Arc::new(AtomicUsize::new(0)), deletes.clone()),
        access.policy.clone(),
        legacy_read_with_verifier().1,
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
fn legacy_cleanup_rejects_unretained_authority_before_native_delete() {
    let access = current_writer_access();
    let deletes = Arc::new(AtomicUsize::new(0));
    let source = NativeProviderCredentialLegacySource::new(
        RecordingLegacyStore::new(Arc::new(AtomicUsize::new(0)), deletes.clone()),
        access.policy.clone(),
        legacy_read_with_verifier().1,
    );
    let command = command(CredentialOperationAction::LegacySourceCleanup);
    let channel = channel();
    let binding = binding(9);
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let authorization = authorization(&issuer, &command, binding, &channel);
    let input = BrokeredLegacySourceDeleteInput::new(command, binding, channel).unwrap();

    assert_eq!(
        source.delete_exact(&effects, authorization, input),
        Err(SecureStoreError::CredentialAccessDenied)
    );
    drop(access);

    assert_eq!(deletes.load(Ordering::SeqCst), 0);
}

struct RecordingLegacyStore {
    loads: Arc<AtomicUsize>,
    deletes: Arc<AtomicUsize>,
    revision: [u8; 16],
}

impl RecordingLegacyStore {
    const fn new(loads: Arc<AtomicUsize>, deletes: Arc<AtomicUsize>) -> Self {
        Self {
            loads,
            deletes,
            revision: [7; 16],
        }
    }
}

impl ProviderCredentialStore for RecordingLegacyStore {
    fn delete_provider_credential(
        &self,
        _provider: ProviderCredentialId,
    ) -> Result<(), SecureStoreError> {
        panic!("legacy cleanup must never fall back to provider-scoped deletion")
    }
    fn migrate_provider_credential_access(
        &self,
        _provider: ProviderCredentialId,
        _current: &ProviderCredentialAccessPolicy,
        _replacement: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        unreachable!()
    }
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
}

impl crate::provider_credential::AuthorizedLegacySourceStore for RecordingLegacyStore {
    fn delete_authorized_legacy_source(
        &self,
        provider: ProviderCredentialId,
        binding: &runne_provider::CredentialLegacyCleanupBinding,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        assert_eq!(provider, ProviderCredentialId::OpenAi);
        crate::provider_credential::source_cleanup::select(
            binding,
            vec![(
                ProviderCredentialSourceRevision::new(self.revision).unwrap(),
                (),
            )],
        )?;
        self.deletes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn load_authorized_legacy_source(
        &self,
        read: runne_provider::AuthorizedCredentialLegacyRead,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<ProviderCredentialSource, SecureStoreError> {
        assert_eq!(read.command().provider().as_str(), "openai");
        assert_eq!(
            read.command().action(),
            CredentialOperationAction::MigrateLegacy
        );
        self.loads.fetch_add(1, Ordering::SeqCst);
        Ok(ProviderCredentialSource::new(
            ProviderCredentialMaterial::new(b"legacy-secret".to_vec()).unwrap(),
            ProviderCredentialSourceRevision::new([7; 16]).unwrap(),
        ))
    }
}

fn command(action: CredentialOperationAction) -> CredentialBrokerCommand {
    cleanup::command(action)
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
