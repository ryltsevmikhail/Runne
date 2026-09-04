use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use runne_provider::{
    BrokerChannelBinding, ClaimedWriterAuthorization, CredentialBindingDigest,
    CredentialBrokerFrame, CredentialOperationAction, CredentialVersionRef,
    CredentialWriterAuthorityPair, NativeCredentialDeletionProof, PendingCredentialSecretOpening,
    ProviderId, SealedCredentialEnvelope,
};

use super::super::migration::{BrokeredCreateInput, BrokeredLegacySourceDeleteInput};
use super::super::writer::{
    BrokeredProviderCredentialWriter, BrokeredProviderCredentialWriterAdapter,
    BrokeredProviderCredentialWriterNative,
};
use crate::{ProviderCredentialAccessPolicy, ProviderCredentialMaterial, SecureStoreError};

#[test]
fn brokered_pair_writer_accepts_only_a_sealed_relay() {
    fn call(
        writer: &dyn BrokeredProviderCredentialWriter,
        authorization: ClaimedWriterAuthorization,
        input: BrokeredCreateInput,
        pending: PendingCredentialSecretOpening,
        envelope: SealedCredentialEnvelope,
    ) {
        let _ = writer.create_sealed_exact(authorization, input, pending, envelope);
    }
    let _ = call;
}

#[test]
fn brokered_provider_credential_rejects_wrong_action_before_adapter_mutation() {
    let mutations = Arc::new(AtomicUsize::new(0));
    let (_, effects) = CredentialWriterAuthorityPair::new().split();
    let writer = BrokeredProviderCredentialWriterAdapter::new(
        effects,
        TestNative(mutations.clone()),
        access(),
    );
    let provider = ProviderId::new("openai").unwrap();
    let revoke = runne_provider::CredentialBrokerCommand::new(
        runne_provider::CredentialOperationId::from_bytes([2; 16]).unwrap(),
        runne_provider::CredentialTicketAttempt::new(1).unwrap(),
        provider.clone(),
        CredentialOperationAction::Revoke,
        runne_provider::CredentialBrokerTarget::Version(
            CredentialVersionRef::new(provider, 1).unwrap(),
        ),
        runne_provider::CredentialLifecycleRevision::new(1).unwrap(),
        runne_provider::CredentialFence::new(1).unwrap(),
        None,
    )
    .unwrap();
    assert!(BrokeredCreateInput::new(revoke, binding(), channel()).is_err());
    assert_eq!(mutations.load(Ordering::SeqCst), 0);
    let _ = writer;
}

#[test]
fn brokered_provider_credential_rejects_binding_substitution_before_adapter_mutation() {
    let mutations = Arc::new(AtomicUsize::new(0));
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let first = command(3, 1);
    let authorization = authorization(&issuer, &first, binding(), &channel());
    let writer = BrokeredProviderCredentialWriterAdapter::new(
        effects,
        TestNative(mutations.clone()),
        access(),
    );
    let binding = binding();
    let channel = channel();
    let command = command(4, 1);
    let input = BrokeredCreateInput::new(command.clone(), binding, channel.clone()).unwrap();
    let sealed =
        runne_provider::sealed_pair_for_test(&command, binding, &channel, b"secret".to_vec())
            .unwrap();
    assert!(
        writer
            .create_sealed_exact(authorization, input, sealed.pending, sealed.envelope)
            .is_err()
    );
    assert_eq!(mutations.load(Ordering::SeqCst), 0);
}

#[test]
fn brokered_provider_credential_consumes_matching_authorization_for_create() {
    let mutations = Arc::new(AtomicUsize::new(0));
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let command = command(5, 1);
    let binding = binding();
    let channel = channel();
    let authorization = authorization(&issuer, &command, binding, &channel);
    let writer = BrokeredProviderCredentialWriterAdapter::new(
        effects,
        TestNative(mutations.clone()),
        access(),
    );
    let sealed =
        runne_provider::sealed_pair_for_test(&command, binding, &channel, b"secret".to_vec())
            .unwrap();
    let input = BrokeredCreateInput::new(command, binding, channel).unwrap();
    writer
        .create_sealed_exact(authorization, input, sealed.pending, sealed.envelope)
        .unwrap();
    assert_eq!(mutations.load(Ordering::SeqCst), 1);
}

#[test]
fn brokered_legacy_source_cleanup_needs_no_version_deletion_proof() {
    let mutations = Arc::new(AtomicUsize::new(0));
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let command = legacy_cleanup_command();
    let authorization = authorization(&issuer, &command, binding(), &channel());
    let writer = BrokeredProviderCredentialWriterAdapter::new(
        effects,
        TestNative(mutations.clone()),
        access(),
    );
    let input = BrokeredLegacySourceDeleteInput::new(command, binding(), channel()).unwrap();
    let (): () = writer
        .delete_legacy_source_exact(authorization, input)
        .unwrap();
    assert_eq!(mutations.load(Ordering::SeqCst), 1);
}

struct TestNative(Arc<AtomicUsize>);

impl BrokeredProviderCredentialWriterNative for TestNative {
    fn preflight_create_exact(
        &self,
        _input: &BrokeredCreateInput,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        Ok(())
    }
    fn create_exact(
        &self,
        _input: &BrokeredCreateInput,
        _material: &ProviderCredentialMaterial,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn delete_exact(
        &self,
        _input: &crate::provider_credential::BrokeredDeleteInput,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<NativeCredentialDeletionProof, SecureStoreError> {
        unreachable!()
    }
    fn import_legacy_exact(
        &self,
        _input: &crate::provider_credential::BrokeredMigrateLegacyInput,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        unreachable!()
    }
    fn delete_legacy_source_exact(
        &self,
        _input: &crate::provider_credential::BrokeredLegacySourceDeleteInput,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn migrate_writer_identity_exact(
        &self,
        _input: &crate::provider_credential::BrokeredWriterIdentityMigrationInput,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        unreachable!()
    }
    fn verify_writer_identity_exact(
        &self,
        _input: &crate::provider_credential::BrokeredWriterIdentityVerificationInput,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        unreachable!()
    }
}

fn authorization(
    issuer: &runne_provider::CredentialWriterClaimIssuer,
    command: &runne_provider::CredentialBrokerCommand,
    binding: CredentialBindingDigest,
    channel: &BrokerChannelBinding,
) -> ClaimedWriterAuthorization {
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

fn binding() -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([9; 32]).unwrap()
}

fn channel() -> BrokerChannelBinding {
    let (_, measurements) = runne_provider::CredentialEnrollmentAuthorityPair::new().split();
    measurements.broker_channel_binding([8; 32]).unwrap()
}

fn command(operation: u8, version: u64) -> runne_provider::CredentialBrokerCommand {
    let provider = ProviderId::new("openai").unwrap();
    runne_provider::CredentialBrokerCommand::new(
        runne_provider::CredentialOperationId::from_bytes([operation; 16]).unwrap(),
        runne_provider::CredentialTicketAttempt::new(1).unwrap(),
        provider.clone(),
        CredentialOperationAction::Pair,
        runne_provider::CredentialBrokerTarget::Version(
            CredentialVersionRef::new(provider, version).unwrap(),
        ),
        runne_provider::CredentialLifecycleRevision::new(1).unwrap(),
        runne_provider::CredentialFence::new(1).unwrap(),
        None,
    )
    .unwrap()
}

fn legacy_cleanup_command() -> runne_provider::CredentialBrokerCommand {
    runne_provider::CredentialBrokerCommand::new(
        runne_provider::CredentialOperationId::from_bytes([6; 16]).unwrap(),
        runne_provider::CredentialTicketAttempt::new(1).unwrap(),
        ProviderId::new("openai").unwrap(),
        CredentialOperationAction::LegacySourceCleanup,
        runne_provider::CredentialBrokerTarget::ExactLegacySource(
            crate::provider_credential::source_cleanup_tests::binding(),
        ),
        runne_provider::CredentialLifecycleRevision::new(2).unwrap(),
        runne_provider::CredentialFence::new(2).unwrap(),
        None,
    )
    .unwrap()
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
