use runne_api::{
    CredentialServiceRegistrationBinding, CredentialServiceSessionAuthenticator, LaunchSecret,
};
use runne_platform_ports::credential_service::{
    CredentialServiceCallContext, CredentialServicePortError, CredentialServicePortFuture,
    CredentialServiceRuntimePort, CredentialServiceRuntimeReply, CredentialServiceRuntimeRequest,
};
use runne_provider::{
    CredentialBrokerCommand, CredentialBrokerTarget, CredentialEnrollmentAuthorityPair,
    CredentialFence, CredentialLifecycleRevision, CredentialOperationAction, CredentialOperationId,
    CredentialServiceIngressRequest, CredentialServiceProtocolCodec, CredentialServiceReply,
    CredentialTicketAttempt, CredentialVersionRef, ProviderId,
};
use std::sync::{Arc, Mutex};

use super::credential_service_registration::{
    ExpectedCredentialServiceRegistration, accept_registration_frames, registration_payload,
};

#[test]
fn service_registration_accepts_only_one_exact_nested_control_payload() {
    let payload = b"RNCRED01-registration";
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
    frame.extend_from_slice(payload);

    assert_eq!(registration_payload(&frame), Ok(payload.as_slice()));
    assert!(registration_payload(payload).is_err());
    frame.push(0);
    assert!(registration_payload(&frame).is_err());
}

#[test]
fn exact_service_registration_claim_and_ack_are_admitted_once() {
    let keys = LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys();
    let authenticator = CredentialServiceSessionAuthenticator::from_protected_activation(&keys);
    let binding = binding();
    let claim = authenticator
        .authenticate_registration(binding.clone())
        .unwrap()
        .into_bytes();
    let verified = authenticator
        .decode_and_verify_registration_for(&claim, &binding, 99)
        .unwrap();
    let acknowledgement = authenticator
        .registration_ack(verified, 99)
        .unwrap()
        .into_bytes();

    let session = accept_registration_frames(
        &keys,
        &ExpectedCredentialServiceRegistration::from_binding(&binding),
        &claim,
        &acknowledgement,
        99,
    )
    .unwrap();
    assert_eq!(session.binding().service_epoch(), binding.service_epoch());
}

#[tokio::test]
async fn registered_runtime_session_arms_exact_mutation_before_writer_handoff() {
    let keys = LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys();
    let binding = binding();
    let authenticator = CredentialServiceSessionAuthenticator::from_protected_activation(&keys);
    let claim = authenticator
        .authenticate_registration(binding.clone())
        .unwrap()
        .into_bytes();
    let verified = authenticator
        .decode_and_verify_registration_for(&claim, &binding, 99)
        .unwrap();
    let acknowledgement = authenticator
        .registration_ack(verified, 99)
        .unwrap()
        .into_bytes();
    let mut session = accept_registration_frames(
        &keys,
        &ExpectedCredentialServiceRegistration::from_binding(&binding),
        &claim,
        &acknowledgement,
        99,
    )
    .unwrap();
    let service = AuthenticatingRuntimePort::new(&keys, [3; 32]);
    let (store, _) = CredentialEnrollmentAuthorityPair::new().split();

    let handoff = session
        .arm_mutation_with_port(
            &service,
            &store.runtime_arm_authority(),
            pair_command(),
            100,
        )
        .await
        .unwrap();

    let observed = service.observed();
    assert_eq!(observed.operation, [8; 16]);
    assert_eq!(observed.attempt, 2);
    assert_eq!(observed.epoch, [2; 16]);
    assert_eq!(
        observed.session,
        [1, 1, 1, 1, 1, 1, 0x70, 1, 0x80, 1, 1, 1, 1, 1, 1, 1]
    );
    assert_eq!(observed.runtime_generation, 11);
    assert_eq!(observed.release, [4; 32]);
    assert_eq!(observed.sequence, 1);
    handoff
        .send::<()>(|bytes| {
            assert!(bytes.len() > 32);
            Ok(())
        })
        .unwrap();
}

#[derive(Clone, Copy)]
struct ObservedArm {
    operation: [u8; 16],
    attempt: u64,
    epoch: [u8; 16],
    session: [u8; 16],
    runtime_generation: u64,
    release: [u8; 32],
    sequence: u64,
}

struct AuthenticatingRuntimePort {
    authenticator: CredentialServiceSessionAuthenticator,
    owner: [u8; 32],
    observed: Arc<Mutex<Option<ObservedArm>>>,
}

impl AuthenticatingRuntimePort {
    fn new(keys: &runne_api::ProtectedActivationKeys, owner: [u8; 32]) -> Self {
        Self {
            authenticator: CredentialServiceSessionAuthenticator::from_protected_activation(keys),
            owner,
            observed: Arc::new(Mutex::new(None)),
        }
    }

    fn observed(&self) -> ObservedArm {
        self.observed.lock().unwrap().unwrap()
    }
}

impl CredentialServiceRuntimePort for AuthenticatingRuntimePort {
    fn arm_mutation(
        &self,
        request: CredentialServiceRuntimeRequest,
        _context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceRuntimeReply> {
        let result = request.with_bytes(|bytes| {
            let payload = self
                .authenticator
                .verify_runtime_request(self.owner, bytes)
                .map_err(|_| CredentialServicePortError::Rejected)?;
            let mut reply = None;
            payload.consume(|bytes| {
                let ingress = CredentialServiceProtocolCodec::decode_runtime_request(bytes)
                    .expect("daemon emitted a canonical runtime request");
                let context = ingress.context();
                let CredentialServiceIngressRequest::RuntimeMutationArm(arm) = ingress else {
                    panic!("daemon emitted a non-arm request");
                };
                *self.observed.lock().unwrap() = Some(ObservedArm {
                    operation: arm.command().operation_id().as_bytes(),
                    attempt: arm.command().ticket_attempt().get(),
                    epoch: arm.epoch().as_bytes(),
                    session: arm.session(),
                    runtime_generation: arm.runtime_generation(),
                    release: arm.release_binding().as_bytes(),
                    sequence: arm.sequence().get(),
                });
                let provider_reply = CredentialServiceProtocolCodec::encode_reply(
                    context,
                    CredentialServiceReply::Armed,
                )
                .unwrap();
                let provider_reply = provider_reply.into_transport_bytes();
                reply = Some(
                    self.authenticator
                        .authenticate_runtime_reply(self.owner, &provider_reply)
                        .unwrap(),
                );
            });
            CredentialServiceRuntimeReply::from_zeroizing(
                reply
                    .expect("verified request produced a reply")
                    .into_transport_bytes(),
            )
        });
        Box::pin(async move { result })
    }

    fn read_metadata(
        &self,
        _request: CredentialServiceRuntimeRequest,
        _context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceRuntimeReply> {
        Box::pin(async { Err(CredentialServicePortError::Rejected) })
    }

    fn read_material(
        &self,
        _request: CredentialServiceRuntimeRequest,
        _context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceRuntimeReply> {
        Box::pin(async { Err(CredentialServicePortError::Rejected) })
    }
}

fn pair_command() -> CredentialBrokerCommand {
    let provider = ProviderId::new("deepseek").unwrap();
    CredentialBrokerCommand::new(
        CredentialOperationId::from_bytes([8; 16]).unwrap(),
        CredentialTicketAttempt::new(2).unwrap(),
        provider.clone(),
        CredentialOperationAction::Pair,
        CredentialBrokerTarget::Version(CredentialVersionRef::new(provider, 3).unwrap()),
        CredentialLifecycleRevision::new(5).unwrap(),
        CredentialFence::new(7).unwrap(),
        None,
    )
    .unwrap()
}

fn binding() -> CredentialServiceRegistrationBinding {
    CredentialServiceRegistrationBinding::new(
        [2; 16],
        [1, 1, 1, 1, 1, 1, 0x70, 1, 0x80, 1, 1, 1, 1, 1, 1, 1],
        11,
        11,
        13,
        14,
        [3; 32],
        [4; 32],
        [5; 16],
        1,
        30_100,
    )
    .unwrap()
}
