use runne_api::{
    CredentialServiceRegistrationBinding, CredentialServiceSessionAuthenticator, LaunchSecret,
};
use runne_platform_ports::credential_service::{
    CredentialServiceCallContext, CredentialServicePortError, CredentialServicePortFuture,
    CredentialServiceRuntimePort, CredentialServiceRuntimeReply, CredentialServiceRuntimeRequest,
};
use runne_provider::{
    CredentialBindingDigest, CredentialEnrollmentAuthorityPair, CredentialFence,
    CredentialLifecycleRevision, CredentialMaterial, CredentialServiceIngressRequest,
    CredentialServiceProtocolCodec, CredentialServiceReply, CredentialVersionRef, ProviderId,
};

use super::credential_service_registration::{
    ExpectedCredentialServiceRegistration, accept_registration_frames,
};

#[tokio::test]
async fn registered_runtime_session_reads_exact_metadata_through_runtime_port() {
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
    let service = MetadataRuntimePort {
        authenticator: CredentialServiceSessionAuthenticator::from_protected_activation(&keys),
        owner: [3; 32],
    };
    let (store, _) = CredentialEnrollmentAuthorityPair::new().split();
    let provider = ProviderId::new("deepseek").unwrap();
    let version = CredentialVersionRef::new(provider, 3).unwrap();

    let present = session
        .read_metadata_with_port(
            &service,
            &store.runtime_read_authority(),
            version,
            CredentialLifecycleRevision::new(5).unwrap(),
            CredentialFence::new(7).unwrap(),
            100,
        )
        .await
        .unwrap();

    assert!(present);
}

#[tokio::test]
async fn registered_runtime_session_reads_material_only_with_effect_receipt() {
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
    let service = MaterialRuntimePort {
        authenticator: CredentialServiceSessionAuthenticator::from_protected_activation(&keys),
        owner: [3; 32],
    };
    let (store, _) = CredentialEnrollmentAuthorityPair::new().split();
    let provider = ProviderId::new("deepseek").unwrap();
    let version = CredentialVersionRef::new(provider, 3).unwrap();
    let receipt = CredentialBindingDigest::from_measured([8; 32]).unwrap();

    let material = session
        .read_material_with_port(
            &service,
            &store.runtime_read_authority(),
            &store.dispatch_effect_receipt_authority(),
            version,
            CredentialLifecycleRevision::new(5).unwrap(),
            CredentialFence::new(7).unwrap(),
            receipt,
            100,
        )
        .await
        .unwrap();

    material.consume(|bytes| assert_eq!(bytes, b"point-use-secret"));
}

struct MetadataRuntimePort {
    authenticator: CredentialServiceSessionAuthenticator,
    owner: [u8; 32],
}

struct MaterialRuntimePort {
    authenticator: CredentialServiceSessionAuthenticator,
    owner: [u8; 32],
}

impl CredentialServiceRuntimePort for MaterialRuntimePort {
    fn arm_mutation(
        &self,
        _request: CredentialServiceRuntimeRequest,
        _context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceRuntimeReply> {
        Box::pin(async { Err(CredentialServicePortError::Rejected) })
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
        request: CredentialServiceRuntimeRequest,
        _context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceRuntimeReply> {
        let result = request.with_bytes(|bytes| {
            let verified = self
                .authenticator
                .verify_runtime_request(self.owner, bytes)
                .map_err(|_| CredentialServicePortError::Rejected)?;
            let mut reply = None;
            verified.consume(|bytes| {
                let request =
                    CredentialServiceProtocolCodec::decode_runtime_request(bytes).unwrap();
                let context = request.context();
                let CredentialServiceIngressRequest::PointOfUseRead(request) = request else {
                    panic!("expected point-of-use read")
                };
                assert_eq!(request.binding().version().provider().as_str(), "deepseek");
                assert_eq!(request.receipt().digest().as_bytes(), [8; 32]);
                let encoded = CredentialServiceProtocolCodec::encode_reply(
                    context,
                    CredentialServiceReply::Material(
                        CredentialMaterial::from_bytes(b"point-use-secret".to_vec()).unwrap(),
                    ),
                )
                .unwrap();
                reply = Some(
                    self.authenticator
                        .authenticate_runtime_reply(self.owner, &encoded.into_transport_bytes())
                        .unwrap(),
                );
            });
            CredentialServiceRuntimeReply::from_zeroizing(reply.unwrap().into_transport_bytes())
        });
        Box::pin(async move { result })
    }
}

impl CredentialServiceRuntimePort for MetadataRuntimePort {
    fn arm_mutation(
        &self,
        _request: CredentialServiceRuntimeRequest,
        _context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceRuntimeReply> {
        Box::pin(async { Err(CredentialServicePortError::Rejected) })
    }

    fn read_metadata(
        &self,
        request: CredentialServiceRuntimeRequest,
        _context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceRuntimeReply> {
        let result = request.with_bytes(|bytes| {
            let verified = self
                .authenticator
                .verify_runtime_request(self.owner, bytes)
                .map_err(|_| CredentialServicePortError::Rejected)?;
            let mut reply = None;
            verified.consume(|bytes| {
                let request =
                    CredentialServiceProtocolCodec::decode_runtime_request(bytes).unwrap();
                let context = request.context();
                let CredentialServiceIngressRequest::MetadataReadback(request) = request else {
                    panic!("expected metadata readback")
                };
                assert_eq!(request.binding().version().provider().as_str(), "deepseek");
                let encoded = CredentialServiceProtocolCodec::encode_reply(
                    context,
                    CredentialServiceReply::Metadata { present: true },
                )
                .unwrap();
                reply = Some(
                    self.authenticator
                        .authenticate_runtime_reply(self.owner, &encoded.into_transport_bytes())
                        .unwrap(),
                );
            });
            CredentialServiceRuntimeReply::from_zeroizing(reply.unwrap().into_transport_bytes())
        });
        Box::pin(async move { result })
    }

    fn read_material(
        &self,
        _request: CredentialServiceRuntimeRequest,
        _context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceRuntimeReply> {
        Box::pin(async { Err(CredentialServicePortError::Rejected) })
    }
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
