use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use runne_platform_ports::credential_service::{
    CredentialServiceCallContext, CredentialServicePortFuture, CredentialServiceWriterPort,
    CredentialServiceWriterReply, CredentialServiceWriterRequest,
};
use runne_provider::{
    ClaimedWriterAuthorization, CredentialBindingDigest, CredentialBrokerFrame,
    CredentialEnrollmentAuthorityPair, CredentialMaterial, CredentialMutationGrant,
    CredentialOperationAction, CredentialRuntimeMutationPlan, CredentialServiceCorrelation,
    CredentialServiceDeadline, CredentialServiceEpoch, CredentialServiceProtocolCodec,
    CredentialServiceReply, CredentialServiceRequestSequence, CredentialWriterAuthorityPair,
};
use runne_secure_store::{
    BrokeredLegacySourceDeleteInput,
    BrokeredProviderCredentialLegacySource, SecureStoreError,
};

#[test]
fn service_migration_reads_legacy_once_then_sends_material_to_writer_port() {
    let command = super::effect_test_support::command(CredentialOperationAction::MigrateLegacy);
    let binding = CredentialBindingDigest::from_measured([13; 32]).unwrap();
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let channel = measurements.broker_channel_binding([11; 32]).unwrap();
    let (issuer, effects) = CredentialWriterAuthorityPair::new().split();
    let pending = issuer.issue_pending_claim(&command, binding, &channel);
    let authorization = issuer
        .claim_accepted(
            pending,
            CredentialBrokerFrame::ClaimAccepted {
                operation_id: command.operation_id(),
                attempt: command.ticket_attempt(),
            },
            &command,
            binding,
            &channel,
        )
        .unwrap();
    let source = RecordingLegacySource(AtomicUsize::new(0));
    let port = ConsumingWriterPort(AtomicBool::new(false));

    super::effect::consume_service_legacy_migration_with_port(
        &port,
        &effects,
        &source,
        service_handoff(command),
        authorization,
        &channel,
        binding,
    )
    .unwrap();

    assert_eq!(source.0.load(Ordering::SeqCst), 1);
    assert!(port.0.load(Ordering::SeqCst));
}

fn service_handoff(
    command: runne_provider::CredentialBrokerCommand,
) -> runne_provider::CredentialWriterBrokerHandoffFrame {
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
    CredentialServiceProtocolCodec::encode_writer_broker_handoff(writer, grant).unwrap()
}

struct RecordingLegacySource(AtomicUsize);

impl BrokeredProviderCredentialLegacySource for RecordingLegacySource {
    fn load_exact(
        &self,
        read: runne_provider::AuthorizedCredentialLegacyRead,
    ) -> Result<runne_provider::CredentialLegacySourceMaterial, SecureStoreError> {
        assert_eq!(read.command().action(), CredentialOperationAction::MigrateLegacy);
        assert_eq!(read.binding(), CredentialBindingDigest::from_measured([13; 32]).unwrap());
        self.0.fetch_add(1, Ordering::SeqCst);
        CredentialMaterial::from_bytes(b"legacy-secret".to_vec()).and_then(|material| runne_provider::CredentialLegacySourceMaterial::new(material, [73; 16]))
            .map_err(|_| SecureStoreError::InvalidProviderCredential)
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

struct ConsumingWriterPort(AtomicBool);

impl CredentialServiceWriterPort for ConsumingWriterPort {
    fn consume_mutation(
        &self,
        request: CredentialServiceWriterRequest,
        _context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceWriterReply> {
        self.0.store(true, Ordering::SeqCst);
        let reply = request.with_bytes(|bytes| {
            let request = CredentialServiceProtocolCodec::decode_writer_request(bytes).unwrap();
            CredentialServiceProtocolCodec::encode_reply(
                request.context(),
                CredentialServiceReply::Consumed,
            )
            .unwrap()
        });
        Box::pin(async move {
            CredentialServiceWriterReply::from_zeroizing(reply.into_transport_bytes())
        })
    }
}
