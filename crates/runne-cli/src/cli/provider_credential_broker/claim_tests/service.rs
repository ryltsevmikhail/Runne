use runne_provider::{
    ClaimedWriterAuthorization, CredentialBindingDigest, CredentialBrokerCommand,
    CredentialBrokerFrame, CredentialBrokerFrameCodec, CredentialMutationGrant,
    CredentialRuntimeMutationPlan, CredentialServiceCorrelation, CredentialServiceDeadline,
    CredentialServiceEpoch, CredentialServiceProtocolCodec, CredentialServiceRequestSequence,
    CredentialWriterAuthorityPair,
};
use runne_secure_store::{
    BrokeredLegacySourceDeleteInput, BrokeredProviderCredentialLegacySource, SecureStoreError,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use super::super::claim::claim_writer_authorization_with_service_parts;
use super::*;

#[test]
fn v3_claim_requires_and_retains_the_exact_service_handoff_after_ack() {
    let command = command(16, CredentialOperationAction::Pair);
    let (mut parts, written) = endpoint(
        issue(command.clone(), binding(), [11; 32]),
        Some(accepted(&command)),
    );
    parts
        .control
        .input
        .get_mut()
        .extend_from_slice(&service_handoff(command.clone()));
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();

    let claimed = claim_writer_authorization_with_service_parts(
        parts.control,
        parts.channel,
        parts.ticket,
        &issuer,
        effects,
        legacy_source(),
        CredentialSecretInputPresence::Present,
        writer_service_configuration(),
    );

    assert!(claimed.is_ok());
    assert_one_claim(&written, true);

    let (parts, _) = endpoint(
        issue(command.clone(), binding(), [11; 32]),
        Some(accepted(&command)),
    );
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    assert!(
        claim_writer_authorization_with_service_parts(
            parts.control,
            parts.channel,
            parts.ticket,
            &issuer,
            effects,
            legacy_source(),
            CredentialSecretInputPresence::Present,
            writer_service_configuration(),
        )
        .is_err()
    );
}

#[test]
fn v3_legacy_cleanup_claim_does_not_wait_for_a_service_handoff() {
    let command = command(17, CredentialOperationAction::LegacySourceCleanup);
    let (parts, written) = endpoint(
        issue(command.clone(), binding(), [11; 32]),
        Some(accepted(&command)),
    );
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();

    let claimed = claim_writer_authorization_with_service_parts(
        parts.control,
        parts.channel,
        parts.ticket,
        &issuer,
        effects,
        legacy_source(),
        CredentialSecretInputPresence::Absent,
        writer_service_configuration(),
    );

    assert!(claimed.is_ok());
    assert_one_claim(&written, false);
}

#[test]
fn v3_legacy_cleanup_executes_only_the_narrow_legacy_delete() {
    let command = command(18, CredentialOperationAction::LegacySourceCleanup);
    let (mut parts, _) = endpoint(
        issue(command.clone(), binding(), [11; 32]),
        Some(accepted(&command)),
    );
    append_release(&mut parts, &command);
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let calls = Arc::new(AtomicUsize::new(0));
    let source = Arc::new(RecordingDeleteSource(calls.clone()));
    let claimed = claim_writer_authorization_with_service_parts(
        parts.control,
        parts.channel,
        parts.ticket,
        &issuer,
        effects,
        source,
        CredentialSecretInputPresence::Absent,
        writer_service_configuration(),
    )
    .unwrap();

    super::super::effect::execute_non_pair_effect(claimed.authorize_without_secret().unwrap())
        .unwrap();

    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// Appends the exact native-effect release that a non-pair claim must read
/// after its acknowledgement before authorizing the effect.
fn append_release(parts: &mut TestClaimParts, command: &CredentialBrokerCommand) {
    let mut encoded = Vec::new();
    CredentialBrokerFrameCodec::write_to(
        &mut encoded,
        CredentialBrokerFrame::NativeEffectRelease {
            operation_id: command.operation_id(),
            attempt: command.ticket_attempt(),
            binding: binding(),
        },
    )
    .expect("release frame");
    parts.control.input.get_mut().extend_from_slice(&encoded);
}

fn service_handoff(command: CredentialBrokerCommand) -> Vec<u8> {
    let (store, _) = CredentialEnrollmentAuthorityPair::new().split();
    let grant = CredentialMutationGrant::generate().unwrap();
    let plan = CredentialRuntimeMutationPlan::issue(
        &store.runtime_arm_authority(),
        command,
        CredentialServiceEpoch::from_bytes([2; 16]).unwrap(),
        [3; 32],
        [4; 16],
        5,
        CredentialBindingDigest::from_measured([6; 32]).unwrap(),
        CredentialServiceRequestSequence::new(1).unwrap(),
        CredentialServiceCorrelation::from_bytes([7; 16]).unwrap(),
        CredentialServiceDeadline::new(10, 20).unwrap(),
        grant.digest(),
    )
    .unwrap();
    let (_, writer) = plan.split();
    CredentialServiceProtocolCodec::encode_writer_broker_handoff(writer, grant)
        .unwrap()
        .into_transport_bytes()
        .to_vec()
}

fn writer_service_configuration() -> runne_macos_xpc::CredentialServiceEndpointConfiguration {
    let requirement = |identifier: &str, hash: char| {
        runne_macos_xpc::CredentialServicePeerRequirement::new(format!(
            "identifier \"{identifier}\" and anchor apple generic and certificate leaf[subject.OU] = \"758F9Z45SR\" and cdhash H\"{}\"",
            hash.to_string().repeat(40)
        ))
        .unwrap()
    };
    runne_macos_xpc::CredentialServiceEndpointConfiguration::new(
        runne_macos_xpc::CredentialServiceEndpointRole::Writer,
        runne_macos_xpc::CredentialServiceEndpointRole::Writer.endpoint_name(),
        requirement("com.runne.credential-service", '4'),
        requirement("runne", '2'),
    )
    .unwrap()
}

struct UnusedLegacySource;

impl BrokeredProviderCredentialLegacySource for UnusedLegacySource {
    fn load_exact(
        &self,
        _read: runne_provider::AuthorizedCredentialLegacyRead,
    ) -> Result<runne_provider::CredentialLegacySourceMaterial, SecureStoreError> {
        Err(SecureStoreError::ProviderCredentialOperationFailed)
    }

    fn delete_exact(
        &self,
        _effects: &runne_provider::CredentialWriterEffectAuthority,
        _authorization: ClaimedWriterAuthorization,
        _input: BrokeredLegacySourceDeleteInput,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::ProviderCredentialOperationFailed)
    }
}

fn legacy_source() -> Arc<dyn BrokeredProviderCredentialLegacySource> {
    Arc::new(UnusedLegacySource)
}

struct RecordingDeleteSource(Arc<AtomicUsize>);

impl BrokeredProviderCredentialLegacySource for RecordingDeleteSource {
    fn load_exact(
        &self,
        _read: runne_provider::AuthorizedCredentialLegacyRead,
    ) -> Result<runne_provider::CredentialLegacySourceMaterial, SecureStoreError> {
        Err(SecureStoreError::ProviderCredentialOperationFailed)
    }

    fn delete_exact(
        &self,
        _effects: &runne_provider::CredentialWriterEffectAuthority,
        _authorization: ClaimedWriterAuthorization,
        _input: BrokeredLegacySourceDeleteInput,
    ) -> Result<(), SecureStoreError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
