use super::*;
use std::io::Read;
use std::os::unix::net::UnixStream;
use std::time::Duration;

fn registered(
    process: &ProtectedBundledRuntimeProcess,
    mutation: &str,
) -> RegisteredCredentialServiceSession {
    let ProtectedProcessActivation::V3 { owned, .. } = &process.activation else {
        panic!()
    };
    let enrollment = owned.enrollment_binding();
    let mut session = *owned.session_id();
    if mutation == "session" {
        session[0] ^= 1;
    }
    let generation = owned.launch_generation();
    let binding = CredentialServiceRegistrationBinding::new(
        [1; 16],
        session,
        generation + u64::from(mutation == "authority"),
        generation + u64::from(mutation == "runtime"),
        enrollment.desktop_supervisor_generation() + u64::from(mutation == "supervisor"),
        1,
        if mutation == "owner" {
            [80; 32]
        } else {
            *enrollment.installation_identity_digest()
        },
        if mutation == "release" {
            [81; 32]
        } else {
            *enrollment.release_tuple_digest()
        },
        [2; 16],
        1,
        if mutation == "expiry" {
            1
        } else {
            unix_millis().unwrap() + 5_000
        },
    )
    .unwrap();
    let other_keys = runne_api::LaunchSecret::from_bytes([99; 32])
        .unwrap()
        .derive_keys();
    let authenticator =
        CredentialServiceSessionAuthenticator::from_protected_activation(if mutation == "keys" {
            &other_keys
        } else {
            &process.keys
        });
    let claim = authenticator
        .authenticate_registration(binding.clone())
        .unwrap();
    let authenticator = if mutation == "ack_keys" {
        CredentialServiceSessionAuthenticator::from_protected_activation(&other_keys)
    } else {
        authenticator
    };
    let bytes = authenticator
        .authenticate_registration(binding.clone())
        .unwrap()
        .into_bytes();
    let verified = authenticator
        .decode_and_verify_registration_for(&bytes, &binding, 0)
        .unwrap();
    let acknowledgement = authenticator.registration_ack(verified, 0).unwrap();
    RegisteredCredentialServiceSession {
        exchange_deadline: (mutation == "exchange_deadline").then_some(0),
        claim,
        acknowledgement,
        configuration: None,
    }
}

#[test]
fn confirmation_rejects_stale_registration_before_writing_to_current_daemon() {
    for mutation in [
        "session",
        "authority",
        "runtime",
        "supervisor",
        "owner",
        "release",
        "expiry",
        "exchange_deadline",
        "keys",
        "ack_keys",
    ] {
        let mut supervisor =
            super::super::test_only_ready_v3_enrollment_supervisor().into_supervisor();
        let process = supervisor.process.as_mut().unwrap();
        let (channel, mut peer) = UnixStream::pair().unwrap();
        process.channel = channel;
        let evidence = registered(process, mutation);
        let result = process.confirm_credential_service_session(evidence);
        peer.set_nonblocking(true).unwrap();
        let mut byte = [0; 1];
        let read = peer.read(&mut byte);
        process.child.kill().unwrap();
        process.child.wait().unwrap();
        assert!(result.is_err(), "accepted {mutation}");
        assert!(
            matches!(read, Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
            "wrote rejected {mutation} registration"
        );
    }
}

#[test]
fn confirmation_delivers_current_authenticated_registration_and_ack() {
    let mut supervisor = super::super::test_only_ready_v3_enrollment_supervisor().into_supervisor();
    let process = supervisor.process.as_mut().unwrap();
    let (channel, mut peer) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    process.channel = channel;
    let evidence = registered(process, "current");
    let expected = evidence.claim.binding().clone();
    let result = process.confirm_credential_service_session(evidence);
    process.child.kill().unwrap();
    process.child.wait().unwrap();
    result.unwrap();
    let claim = super::super::read_frame(&mut peer).unwrap();
    let ack = super::super::read_frame(&mut peer).unwrap();
    let authenticator =
        CredentialServiceSessionAuthenticator::from_protected_activation(&process.keys);
    authenticator
        .decode_and_verify_registration_for(&claim[4..], &expected, unix_millis().unwrap())
        .unwrap();
    authenticator
        .decode_and_verify_ack_for(&ack[4..], &expected, unix_millis().unwrap())
        .unwrap();
}
