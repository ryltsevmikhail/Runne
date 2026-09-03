use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use runne_api::{
    CredentialServiceRegistrationBinding, CredentialServiceSessionAuthenticator, LaunchSecret,
};
use runne_platform_ports::credential_service::{
    CredentialServiceCallContext, CredentialServiceDesktopPort, CredentialServiceDesktopReply,
    CredentialServiceDesktopRequest, CredentialServicePortFuture,
};
use runne_provider::{
    CredentialServiceProtocolCodec, CredentialServiceReply, CredentialServiceRequest,
};
use zeroize::Zeroizing;

use super::credential_service_session::{
    CredentialServiceRegistrationFacts, bounded_session_expiry_unix_millis,
    protected_control_frame, register_credential_service_session_with_port,
};

const EPOCH: [u8; 16] = [21; 16];
const NONCE: [u8; 16] = [22; 16];

struct RealWireDesktopPeer {
    accepted: Mutex<Option<CredentialServiceRegistrationBinding>>,
}

impl RealWireDesktopPeer {
    const fn new() -> Self {
        Self {
            accepted: Mutex::new(None),
        }
    }
}

impl CredentialServiceDesktopPort for RealWireDesktopPeer {
    fn challenge(
        &self,
        request: CredentialServiceDesktopRequest,
        _context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceDesktopReply> {
        Box::pin(async move {
            let decoded =
                request.with_bytes(CredentialServiceProtocolCodec::decode_desktop_request);
            if !matches!(
                decoded,
                Ok(runne_provider::CredentialServiceIngressRequest::RegistrationChallenge)
            ) {
                return Err(
                    runne_platform_ports::credential_service::CredentialServicePortError::Rejected,
                );
            }
            let context = CredentialServiceRequest::RegistrationChallenge.context();
            let epoch =
                runne_provider::CredentialServiceEpoch::from_bytes(EPOCH).map_err(|_| {
                    runne_platform_ports::credential_service::CredentialServicePortError::Rejected
                })?;
            let reply = CredentialServiceProtocolCodec::encode_reply(
                context,
                CredentialServiceReply::RegistrationChallenge {
                    epoch,
                    nonce: NONCE,
                },
            )
            .map_err(|_| {
                runne_platform_ports::credential_service::CredentialServicePortError::Rejected
            })?;
            CredentialServiceDesktopReply::from_zeroizing(reply.into_transport_bytes())
        })
    }

    fn register(
        &self,
        request: CredentialServiceDesktopRequest,
        _context: CredentialServiceCallContext,
    ) -> CredentialServicePortFuture<'_, CredentialServiceDesktopReply> {
        Box::pin(async move {
            let now = unix_millis();
            let mut accepted = None;
            let registration = request
                .with_bytes(|bytes| {
                    CredentialServiceSessionAuthenticator::accept_registration_install_with_policy(
                        bytes,
                        now,
                        |binding| {
                            accepted = Some(binding.clone());
                            Ok(())
                        },
                    )
                })
                .map_err(|_| {
                    runne_platform_ports::credential_service::CredentialServicePortError::Rejected
                })?;
            let (_, ack) = registration.complete(now).map_err(|_| {
                runne_platform_ports::credential_service::CredentialServicePortError::Rejected
            })?;
            *self.accepted.lock().unwrap() = accepted;
            CredentialServiceDesktopReply::from_zeroizing(Zeroizing::new(ack.into_bytes()))
        })
    }
}

#[tokio::test]
async fn desktop_registration_challenges_installs_and_verifies_one_exact_session() {
    let now = unix_millis();
    let registration_ttl = u64::try_from(Duration::from_secs(30).as_millis()).unwrap();
    let peer = RealWireDesktopPeer::new();
    let auth = CredentialServiceSessionAuthenticator::from_protected_activation(
        &LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys(),
    );
    let facts = CredentialServiceRegistrationFacts::new(
        uuid(1),
        2,
        3,
        4,
        5,
        [6; 32],
        [8; 32],
        1,
        now + registration_ttl,
    )
    .unwrap();

    let registered = register_credential_service_session_with_port(&peer, auth, facts)
        .await
        .unwrap();
    assert_eq!(registered.service_epoch(), &EPOCH);
    assert_eq!(registered.installed_generation(), 5);
    let (challenge_nonce, release_binding) = {
        let guard = peer.accepted.lock().unwrap();
        let accepted = guard.as_ref().unwrap();
        let facts = (*accepted.challenge_nonce(), *accepted.release_binding());
        drop(guard);
        facts
    };
    assert_eq!(challenge_nonce, NONCE);
    assert_eq!(release_binding, [8; 32]);
}

#[test]
fn service_registration_uses_unix_time_and_expires_before_the_parent_session() {
    let now = 1_000_000_u64;
    let expires = bounded_session_expiry_unix_millis(now).unwrap();
    let renew_after =
        u64::try_from(runne_api::PROTECTED_BUNDLED_SESSION_RENEW_AFTER.as_millis()).unwrap();
    let parent_ttl = u64::try_from(runne_api::LOCAL_RUNTIME_SESSION_TTL.as_millis()).unwrap();
    assert_eq!(expires - now, renew_after);
    assert!(expires - now < parent_ttl);
}

#[test]
fn service_registration_payload_is_nested_in_one_exact_protected_control_frame() {
    let payload = b"RNCRED01-registration".to_vec();
    let framed = protected_control_frame(payload.clone()).unwrap();

    assert_eq!(
        u32::from_be_bytes(framed[..4].try_into().unwrap()) as usize,
        payload.len()
    );
    assert_eq!(&framed[4..], payload);
    assert!(protected_control_frame(Vec::new()).is_err());
    assert!(
        protected_control_frame(vec![0; runne_api::CREDENTIAL_SERVICE_MAX_FRAME_BYTES + 1])
            .is_err()
    );
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}

const fn uuid(byte: u8) -> [u8; 16] {
    let mut value = [byte; 16];
    value[6] = 0x70 | (byte & 0x0f);
    value[8] = 0x80 | (byte & 0x3f);
    value
}
