use runne_api::{
    CredentialServiceRegistrationBinding, CredentialServiceSessionAuthenticator, LaunchSecret,
};
use runne_platform_ports::credential_service::{
    CredentialServiceCallContext, CredentialServicePortError, CredentialServicePortFuture,
    CredentialServiceRuntimePort, CredentialServiceRuntimeReply, CredentialServiceRuntimeRequest,
};
use runne_provider::{
    CredentialEnrollmentAuthorityPair, CredentialFence, CredentialLifecycleRevision,
    CredentialServiceDisposition, CredentialServiceEpoch, CredentialServiceProtocolCodec,
    CredentialServiceReply, CredentialVersionRef, ProviderId,
};

use super::super::{ExpectedCredentialServiceRegistration, accept_registration_frames};

#[tokio::test]
async fn session_missing_preserves_exact_epoch_for_bounded_rejoin() {
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
    let missing = CredentialServiceEpoch::from_bytes([9; 16]).unwrap();
    let port = MissingRuntimePort {
        authenticator,
        owner: [3; 32],
        missing,
    };
    let (store, _) = CredentialEnrollmentAuthorityPair::new().split();

    let result = session
        .read_metadata_with_port(
            &port,
            &store.runtime_read_authority(),
            CredentialVersionRef::new(ProviderId::new("deepseek").unwrap(), 3).unwrap(),
            CredentialLifecycleRevision::new(5).unwrap(),
            CredentialFence::new(7).unwrap(),
            100,
        )
        .await;

    assert_eq!(
        result,
        Err(runne_api::ProviderCredentialEnrollmentHostError::Unavailable)
    );
    assert_eq!(session.take_missing_epoch(), Some(missing));
    assert_eq!(session.take_missing_epoch(), None);
}

struct MissingRuntimePort {
    authenticator: CredentialServiceSessionAuthenticator,
    owner: [u8; 32],
    missing: CredentialServiceEpoch,
}

impl CredentialServiceRuntimePort for MissingRuntimePort {
    fn arm_mutation(
        &self,
        _: CredentialServiceRuntimeRequest,
        _: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceRuntimeReply> {
        Box::pin(async { Err(CredentialServicePortError::Rejected) })
    }

    fn read_metadata(
        &self,
        request: CredentialServiceRuntimeRequest,
        _: CredentialServiceCallContext,
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
                let encoded = CredentialServiceProtocolCodec::encode_reply(
                    request.context(),
                    CredentialServiceReply::Rejected(
                        CredentialServiceDisposition::SessionMissing {
                            current_epoch: self.missing,
                        },
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

    fn read_material(
        &self,
        _: CredentialServiceRuntimeRequest,
        _: CredentialServiceCallContext,
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

#[test]
fn only_transport_terminal_states_request_reconnection() {
    use CredentialServicePortError as Error;

    for error in [
        Error::Unavailable,
        Error::TimedOut,
        Error::Cancelled,
        Error::Interrupted,
        Error::Invalidated,
        Error::OutcomeUnknown,
    ] {
        assert!(super::is_transport_failure(error));
    }
    for error in [Error::Rejected, Error::Unsupported, Error::InvalidReply] {
        assert!(!super::is_transport_failure(error));
    }
}
