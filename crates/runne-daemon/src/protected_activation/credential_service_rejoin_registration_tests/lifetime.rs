use super::*;
use runne_platform_ports::credential_service::*;
use runne_provider::*;
use std::sync::Mutex;

const PARENT_EXPIRY: u64 = 480_100;

#[tokio::test]
async fn post_rejoin_read_survives_five_seconds_but_not_parent_expiry() {
    exercise(false).await;
}

#[tokio::test]
async fn post_rejoin_arm_survives_five_seconds_but_not_parent_expiry() {
    exercise(true).await;
}

async fn exercise(arm: bool) {
    let keys = LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys();
    let requested = CredentialServiceRejoinBinding::new(
        [9; 16],
        uuid(1),
        11,
        11,
        13,
        14,
        [3; 32],
        [4; 32],
        2,
        5_100,
    )
    .unwrap();
    let binding = CredentialServiceRegistrationBinding::new(
        [9; 16],
        uuid(1),
        11,
        11,
        13,
        14,
        [3; 32],
        [4; 32],
        [6; 16],
        2,
        PARENT_EXPIRY,
    )
    .unwrap();
    let (claim, ack) = registration_frames(&keys, &binding);
    let expected = ExpectedCredentialServiceRegistration::from_rejoin(&requested, PARENT_EXPIRY);
    let mut session = accept_registration_frames(&keys, &expected, &claim, &ack, 100).unwrap();
    let service = RuntimePeer {
        auth: CredentialServiceSessionAuthenticator::from_protected_activation(&keys),
        deadlines: Mutex::new(Vec::new()),
    };
    let (authority, _) = CredentialEnrollmentAuthorityPair::new().split();
    // Inject time directly; no wall-clock waiting or old mutation grant reuse.
    for now in [5_101, PARENT_EXPIRY - 1, PARENT_EXPIRY, PARENT_EXPIRY + 1] {
        let version = CredentialVersionRef::new(ProviderId::new("deepseek").unwrap(), 3).unwrap();
        let revision = CredentialLifecycleRevision::new(5).unwrap();
        let fence = CredentialFence::new(7).unwrap();
        let calls_before = service.deadlines.lock().unwrap().len();
        let result = if arm {
            let command = CredentialBrokerCommand::new(
                CredentialOperationId::from_bytes([8; 16]).unwrap(),
                CredentialTicketAttempt::new(2).unwrap(),
                version.provider().clone(),
                CredentialOperationAction::Pair,
                CredentialBrokerTarget::Version(version),
                revision,
                fence,
                None,
            )
            .unwrap();
            session
                .arm_mutation_with_port(&service, &authority.runtime_arm_authority(), command, now)
                .await
                .map(|_| ())
        } else {
            session
                .read_metadata_with_port(
                    &service,
                    &authority.runtime_read_authority(),
                    version,
                    revision,
                    fence,
                    now,
                )
                .await
                .map(|_| ())
        };
        assert_eq!(result.is_ok(), now < PARENT_EXPIRY);
        let deadlines = service.deadlines.lock().unwrap();
        if now < PARENT_EXPIRY {
            assert_eq!(deadlines.len(), calls_before + 1);
            assert_eq!(
                *deadlines.last().unwrap(),
                (now + 30_000).min(PARENT_EXPIRY)
            );
        } else {
            assert_eq!(
                deadlines.len(),
                calls_before,
                "expired request reached transport"
            );
        }
    }
}

struct RuntimePeer {
    auth: CredentialServiceSessionAuthenticator,
    deadlines: Mutex<Vec<u64>>,
}

impl RuntimePeer {
    fn reply(
        &self,
        request: CredentialServiceRuntimeRequest,
    ) -> Result<CredentialServiceRuntimeReply, CredentialServicePortError> {
        request.with_bytes(|bytes| {
            let verified = self
                .auth
                .verify_runtime_request([3; 32], bytes)
                .map_err(|_| CredentialServicePortError::Rejected)?;
            let mut response = None;
            verified.consume(|bytes| {
                let request =
                    CredentialServiceProtocolCodec::decode_runtime_request(bytes).unwrap();
                let context = request.context();
                let (deadline, reply) = match request {
                    CredentialServiceIngressRequest::RuntimeMutationArm(arm) => {
                        (arm.deadline(), CredentialServiceReply::Armed)
                    }
                    CredentialServiceIngressRequest::MetadataReadback(read) => (
                        read.binding().deadline(),
                        CredentialServiceReply::Metadata { present: true },
                    ),
                    _ => panic!("unexpected runtime request"),
                };
                self.deadlines
                    .lock()
                    .unwrap()
                    .push(deadline.expires_at_unix_millis());
                let encoded = CredentialServiceProtocolCodec::encode_reply(context, reply).unwrap();
                response = Some(
                    self.auth
                        .authenticate_runtime_reply([3; 32], &encoded.into_transport_bytes())
                        .unwrap(),
                );
            });
            CredentialServiceRuntimeReply::from_zeroizing(response.unwrap().into_transport_bytes())
        })
    }
}

impl CredentialServiceRuntimePort for RuntimePeer {
    fn arm_mutation(
        &self,
        request: CredentialServiceRuntimeRequest,
        _: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceRuntimeReply> {
        Box::pin(async move { self.reply(request) })
    }
    fn read_metadata(
        &self,
        request: CredentialServiceRuntimeRequest,
        _: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceRuntimeReply> {
        Box::pin(async move { self.reply(request) })
    }
    fn read_material(
        &self,
        _: CredentialServiceRuntimeRequest,
        _: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceRuntimeReply> {
        Box::pin(async { Err(CredentialServicePortError::Rejected) })
    }
}
