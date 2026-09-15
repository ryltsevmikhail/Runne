use std::sync::{Arc, Mutex};

use runne_provider::{
    BrokerChannelBinding, ClaimedWriterAuthorization, CredentialBindingDigest,
    CredentialBrokerCommand, CredentialBrokerFrame, CredentialBrokerTarget, CredentialFence,
    CredentialLifecycleRevision, CredentialOperationAction, CredentialOperationId,
    CredentialTicketAttempt, CredentialVersionRef, CredentialWriterAuthorityPair,
    NativeCredentialDeletionProof, ProviderId,
};

use super::{
    BrokeredProviderCredentialWriter, BrokeredProviderCredentialWriterAdapter,
    BrokeredProviderCredentialWriterNative,
};
use crate::{
    BrokeredCreateInput, BrokeredDeleteInput, BrokeredLegacySourceDeleteInput,
    BrokeredMigrateLegacyInput, BrokeredWriterIdentityMigrationInput,
    BrokeredWriterIdentityVerificationInput, MAX_PROVIDER_CREDENTIAL_BYTES,
    ProviderCredentialAccessPolicy, ProviderCredentialMaterial, SecureStoreError,
};

#[test]
fn pair_preflight_failure_wins_over_a_tampered_envelope_without_create() {
    let command = command(1);
    let binding = binding();
    let channel = channel();
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let native = PairNative::failing();
    let creates = native.creates.clone();
    let writer = BrokeredProviderCredentialWriterAdapter::new(effects, native, access());
    let input = BrokeredCreateInput::new(command.clone(), binding, channel.clone()).unwrap();
    let fixture =
        runne_provider::sealed_pair_for_test(&command, binding, &channel, b"secret".to_vec())
            .unwrap();
    let encoded = runne_provider::CredentialSecretEnvelopeCodec::encode(&fixture.envelope).unwrap();
    let mut tampered = encoded.to_vec();
    *tampered.last_mut().unwrap() ^= 1;
    let envelope = runne_provider::CredentialSecretEnvelopeCodec::decode(&tampered).unwrap();

    assert_eq!(
        writer.create_sealed_exact(
            authorization(&issuer, &command, binding, &channel),
            input,
            fixture.pending,
            envelope
        ),
        Err(SecureStoreError::CredentialIdentityMismatch)
    );
    assert_eq!(*creates.lock().unwrap(), 0);
}

#[test]
fn exact_sealed_pair_reaches_native_create_with_temporary_material() {
    let command = command(2);
    let binding = binding();
    let channel = channel();
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let native = PairNative::ready();
    let material = native.material.clone();
    let writer = BrokeredProviderCredentialWriterAdapter::new(effects, native, access());
    let input = BrokeredCreateInput::new(command.clone(), binding, channel.clone()).unwrap();
    let fixture =
        runne_provider::sealed_pair_for_test(&command, binding, &channel, b"secret".to_vec())
            .unwrap();

    writer
        .create_sealed_exact(
            authorization(&issuer, &command, binding, &channel),
            input,
            fixture.pending,
            fixture.envelope,
        )
        .unwrap();
    assert_eq!(
        material.lock().unwrap().as_deref(),
        Some(b"secret".as_slice())
    );
}

#[test]
fn oauth_pair_rewrites_only_admitted_version_before_native_create() {
    let command = oauth_command(3, 7);
    let binding = binding();
    let channel = channel();
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let native = PairNative::ready();
    let material = native.material.clone();
    let writer = BrokeredProviderCredentialWriterAdapter::new(effects, native, access());
    let input = BrokeredCreateInput::new(command.clone(), binding, channel.clone()).unwrap();
    let payload = br#"{"schema":"runne.oauth-import/v1","provider":"github-copilot","access_token":"session","refresh_token":null,"account_id":null,"expires_at_unix_seconds":4000000000}"#;
    let fixture =
        runne_provider::sealed_pair_for_test(&command, binding, &channel, payload.to_vec())
            .unwrap();

    writer
        .create_sealed_exact(
            authorization(&issuer, &command, binding, &channel),
            input,
            fixture.pending,
            fixture.envelope,
        )
        .unwrap();
    let stored = material.lock().unwrap().clone().unwrap();
    let value: serde_json::Value = serde_json::from_slice(&stored).unwrap();
    assert_eq!(value["credential_version"], 7);
    assert_eq!(value["provider"], "github-copilot");
}

#[path = "oauth_large_pair_tests.rs"]
mod oauth_large_pair_tests;

#[test]
fn oauth_pair_rejects_payload_version_drift_before_native_create() {
    let command = oauth_command(4, 7);
    let binding = binding();
    let channel = channel();
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let native = PairNative::ready();
    let creates = native.creates.clone();
    let writer = BrokeredProviderCredentialWriterAdapter::new(effects, native, access());
    let input = BrokeredCreateInput::new(command.clone(), binding, channel.clone()).unwrap();
    let payload = br#"{"schema":"runne.oauth-import/v1","provider":"github-copilot","credential_version":99,"access_token":"session","refresh_token":null,"account_id":null,"expires_at_unix_seconds":4000000000}"#;
    let fixture =
        runne_provider::sealed_pair_for_test(&command, binding, &channel, payload.to_vec())
            .unwrap();

    assert_eq!(
        writer.create_sealed_exact(
            authorization(&issuer, &command, binding, &channel),
            input,
            fixture.pending,
            fixture.envelope,
        ),
        Err(SecureStoreError::InvalidProviderCredential)
    );
    assert_eq!(*creates.lock().unwrap(), 0);
}

struct PairNative {
    preflight_fails: bool,
    creates: Arc<Mutex<usize>>,
    material: Arc<Mutex<Option<Vec<u8>>>>,
}

impl PairNative {
    fn failing() -> Self {
        Self {
            preflight_fails: true,
            creates: Arc::new(Mutex::new(0)),
            material: Arc::new(Mutex::new(None)),
        }
    }
    fn ready() -> Self {
        Self {
            preflight_fails: false,
            creates: Arc::new(Mutex::new(0)),
            material: Arc::new(Mutex::new(None)),
        }
    }
}

impl BrokeredProviderCredentialWriterNative for PairNative {
    fn preflight_create_exact(
        &self,
        _: &BrokeredCreateInput,
        _: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        (!self.preflight_fails)
            .then_some(())
            .ok_or(SecureStoreError::CredentialIdentityMismatch)
    }
    fn create_exact(
        &self,
        _: &BrokeredCreateInput,
        material: &ProviderCredentialMaterial,
        _: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        *self.creates.lock().unwrap() += 1;
        *self.material.lock().unwrap() = Some(material.with_bytes(ToOwned::to_owned));
        Ok(())
    }
    fn delete_exact(
        &self,
        _: &BrokeredDeleteInput,
        _: &ProviderCredentialAccessPolicy,
    ) -> Result<NativeCredentialDeletionProof, SecureStoreError> {
        unreachable!()
    }
    fn import_legacy_exact(
        &self,
        _: &BrokeredMigrateLegacyInput,
        _: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        unreachable!()
    }
    fn delete_legacy_source_exact(
        &self,
        _: &BrokeredLegacySourceDeleteInput,
        _: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        unreachable!()
    }
    fn migrate_writer_identity_exact(
        &self,
        _: &BrokeredWriterIdentityMigrationInput,
        _: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        unreachable!()
    }
    fn verify_writer_identity_exact(
        &self,
        _: &BrokeredWriterIdentityVerificationInput,
        _: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        unreachable!()
    }
}

fn authorization(
    issuer: &runne_provider::CredentialWriterClaimIssuer,
    command: &CredentialBrokerCommand,
    binding: CredentialBindingDigest,
    channel: &BrokerChannelBinding,
) -> ClaimedWriterAuthorization {
    issuer
        .claim_accepted(
            issuer.issue_pending_claim(command, binding, channel),
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
    runne_provider::CredentialEnrollmentAuthorityPair::new()
        .split()
        .1
        .broker_channel_binding([8; 32])
        .unwrap()
}
fn command(id: u8) -> CredentialBrokerCommand {
    command_for_provider(id, 1, "openai")
}
fn oauth_command(id: u8, version: u64) -> CredentialBrokerCommand {
    command_for_provider(id, version, "github-copilot")
}
fn command_for_provider(id: u8, version: u64, provider_name: &str) -> CredentialBrokerCommand {
    let provider = ProviderId::new(provider_name).unwrap();
    CredentialBrokerCommand::new(
        CredentialOperationId::from_bytes([id; 16]).unwrap(),
        CredentialTicketAttempt::new(1).unwrap(),
        provider.clone(),
        CredentialOperationAction::Pair,
        CredentialBrokerTarget::Version(CredentialVersionRef::new(provider, version).unwrap()),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        None,
    )
    .unwrap()
}
fn access() -> ProviderCredentialAccessPolicy {
    let executable = std::env::current_exe().unwrap();
    ProviderCredentialAccessPolicy::new(&executable, &executable).unwrap()
}
