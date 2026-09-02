use runne_provider::{
    CredentialServiceDisposition, CredentialServiceEndpointRole, CredentialServiceProtocolCodec,
    CredentialServiceReply, CredentialServiceRequest,
};

use super::super::CredentialServiceCore;
use super::support::{EPOCH, OWNER, binding_for_owner, issue_challenge_at, replay_register};

#[test]
fn capacity_rejection_does_not_evict_first_live_challenge() {
    let mut core = CredentialServiceCore::with_test_epoch(EPOCH).unwrap();
    for value in 1..=64 {
        issue_challenge_at(&mut core, [value; 16], 10);
    }
    let request = CredentialServiceRequest::RegistrationChallenge;
    let context = request.context();
    let frame = CredentialServiceProtocolCodec::encode_request(request).unwrap();
    let mut bytes = Vec::new();
    frame
        .send(|value| {
            bytes.extend_from_slice(value);
            Ok::<(), ()>(())
        })
        .unwrap();
    let rejected = core
        .challenge_with_test_nonce(CredentialServiceEndpointRole::Desktop, &bytes, 10, [65; 16])
        .unwrap();
    let mut reply = Vec::new();
    rejected
        .send(|value| {
            reply.extend_from_slice(value);
            Ok::<(), ()>(())
        })
        .unwrap();
    assert!(matches!(
        CredentialServiceProtocolCodec::decode_desktop_reply(&reply, context),
        Ok(CredentialServiceReply::Rejected(
            CredentialServiceDisposition::Unavailable
        ))
    ));
    let binding = binding_for_owner(OWNER, [1; 16], 2, 12, 14, 6_000);
    assert!(
        replay_register(
            &mut core,
            7,
            binding,
            CredentialServiceEndpointRole::Desktop
        )
        .is_ok()
    );
}
