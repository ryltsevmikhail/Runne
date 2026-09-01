use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::ProtectedActivationChannel;
use super::control_v3::enrollment_transcript_allows_rotation;
use super::control_v3::run_control_loop_v3;
use runne_api::{
    ActivationDispositionV1, ApiPrincipalId, CredentialBrokerTransferAuthenticator,
    DaemonInstanceId, EventLogLineageId, ExecutableIdentityV1, LaunchAuthorityValidationV1,
    LaunchSecret, PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID,
    ProtectedCredentialEnrollmentLaunchBindingV1, ProtectedCredentialEnrollmentLaunchRequestV3,
    ProtectedCredentialEnrollmentRenewRequestV3, ProtectedCredentialEnrollmentRenewTicketV3,
    ProtectedCredentialEnrollmentShutdownAckV3, ProtectedCredentialEnrollmentShutdownV3,
    ProtectedLaunchRequestV1, ProtectedOwnedLaunchV2, ProtectedReadyV1, ProtectedRenewRequestV1,
    ProtectedRenewRequestV2, ProtectedRuntimeProfileV1, ProtectedShutdownV1, ProtectedShutdownV2,
    ProviderActivationBindingV1, RuntimeSessionBinding, StableRuntimeBinding,
    StableRuntimeBindingV1,
};
use runne_application::local_session::LocalSessionService;
use runne_domain::event::Sensitivity;

fn id(byte: u8) -> [u8; 16] {
    let mut value = [byte; 16];
    value[6] = 0x70 | (byte & 0x0f);
    value[8] = 0x80 | (byte & 0x3f);
    value
}

fn profile() -> ProtectedRuntimeProfileV1 {
    ProtectedRuntimeProfileV1::new(
        PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID,
        1,
        "fixture",
        [1; 32],
        [2; 32],
    )
    .unwrap()
}

fn launch() -> (
    ProtectedLaunchRequestV1,
    ProtectedCredentialEnrollmentLaunchBindingV1,
    runne_api::ProtectedActivationKeys,
    runne_api::DaemonEnrollmentLaunchPreludeV1,
) {
    let request = ProtectedLaunchRequestV1::new(
        id(1),
        id(2),
        LaunchSecret::from_bytes([3; 32]).unwrap(),
        10,
        20,
        "local-owner",
        profile(),
        ExecutableIdentityV1::new([4; 32], [5; 32], 1).unwrap(),
        "/tmp/runtime".into(),
        ActivationDispositionV1::FirstActivation,
    )
    .unwrap();
    let keys = request.derive_keys();
    let prelude = runne_api::DaemonEnrollmentLaunchPreludeV1::macos_arm64(
        request.launch_authority_id(),
        request.desktop_host_instance_id(),
        [10; 32],
        [11; 32],
        [12; 32],
        [6; 32],
        [9; 32],
        1,
        10,
        20,
    )
    .unwrap();
    let commitment = CredentialBrokerTransferAuthenticator::from_protected_activation(&keys)
        .enrollment_launch_commitment(&prelude);
    let binding = ProtectedCredentialEnrollmentLaunchBindingV1::macos_apple_silicon(
        [6; 32], [7; 32], [8; 32], [9; 32], 1, commitment,
    )
    .unwrap();
    (request, binding, keys, prelude)
}

fn validation<'a>(request: &'a ProtectedLaunchRequestV1) -> LaunchAuthorityValidationV1<'a> {
    LaunchAuthorityValidationV1 {
        principal_id: "local-owner",
        profile: request.profile(),
        executable: request.executable(),
    }
}

fn enrollment_request() -> (
    ProtectedCredentialEnrollmentLaunchRequestV3,
    ProtectedCredentialEnrollmentLaunchBindingV1,
    runne_api::ProtectedActivationKeys,
    runne_api::DaemonEnrollmentLaunchPreludeV1,
) {
    let (request, binding, keys, prelude) = launch();
    (
        ProtectedCredentialEnrollmentLaunchRequestV3::new(
            request,
            ProviderActivationBindingV1::openai_responses_text_v1(),
            binding.clone(),
        )
        .unwrap(),
        binding,
        keys,
        prelude,
    )
}

#[path = "enrollment_v3_tests/expectation.rs"]
mod expectation;
#[path = "enrollment_v3_tests/legacy_rejection.rs"]
mod legacy_rejection;
#[path = "enrollment_v3_tests/ticket_clock.rs"]
mod ticket_clock;

pub(crate) fn owned_and_sessions() -> (
    runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    runne_api::ProtectedActivationKeys,
    Arc<Mutex<LocalSessionService>>,
) {
    let (launch, binding, keys, _) = enrollment_request();
    let stable =
        StableRuntimeBindingV1::new(id(10), "local-owner", id(11), "fixture", [1; 32], [2; 32])
            .unwrap();
    let ready = ProtectedReadyV1::new(
        id(1),
        id(2),
        launch.executable().clone(),
        profile(),
        stable,
        id(12),
        1,
        id(13),
        "https://127.0.0.1",
        [14; 32],
        vec![15],
        vec!["provider.enroll".into()],
    )
    .unwrap();
    let mut ready = runne_api::ProtectedCredentialEnrollmentReadyV3::new(
        ready,
        ProviderActivationBindingV1::openai_responses_text_v1(),
        binding,
        runne_api::ProviderActivationReadinessV1::CredentialMissing,
    )
    .unwrap();
    ready.sign(&launch, &keys).unwrap();
    let binding = RuntimeSessionBinding::new(
        StableRuntimeBinding::new(
            id(10),
            ApiPrincipalId::new("local-owner").unwrap(),
            EventLogLineageId::from_bytes(id(11)),
            "fixture",
            [1; 32],
            [2; 32],
        )
        .unwrap(),
        DaemonInstanceId::from_bytes(id(12)),
        1,
        id(13),
        0,
        Sensitivity::Public,
        [14; 32],
    )
    .unwrap();
    (
        ready.owned_launch(),
        keys,
        Arc::new(Mutex::new(
            LocalSessionService::new_protected(
                binding,
                [16; 32],
                Duration::ZERO,
                Duration::from_secs(30),
            )
            .unwrap(),
        )),
    )
}

pub(crate) fn read_frame(stream: &mut UnixStream) -> Vec<u8> {
    let mut prefix = [0; 4];
    stream.read_exact(&mut prefix).unwrap();
    let mut frame = vec![0; u32::from_be_bytes(prefix) as usize + 4];
    frame[..4].copy_from_slice(&prefix);
    stream.read_exact(&mut frame[4..]).unwrap();
    frame
}

#[test]
fn v3_control_preserves_exact_binding_across_renewal_and_shutdown() {
    let (owned, keys, sessions) = owned_and_sessions();
    let (mut client, server) = UnixStream::pair().unwrap();
    let server = std::thread::spawn(move || {
        run_control_loop_v3(
            ProtectedActivationChannel::new(server).unwrap(),
            keys,
            owned,
            sessions,
            Arc::new(|| Duration::from_secs(1)),
            Arc::new(|| Ok(1_000)),
            super::enrollment_control_transition::DaemonEnrollmentRendezvous::for_test(),
        )
    });
    let (owned, keys, _) = owned_and_sessions();
    let mut renewal = ProtectedCredentialEnrollmentRenewRequestV3::new(owned, 1, [17; 32]).unwrap();
    renewal.sign(&keys);
    client.write_all(&renewal.encode_frame().unwrap()).unwrap();
    let ticket =
        ProtectedCredentialEnrollmentRenewTicketV3::decode_frame(&read_frame(&mut client)).unwrap();
    let next = ticket
        .verify_exact_at(&renewal, 1_000, &keys)
        .unwrap()
        .next_owned_launch();
    assert_eq!(
        next.enrollment_binding(),
        renewal.owned_launch().enrollment_binding()
    );
    let mut shutdown = ProtectedCredentialEnrollmentShutdownV3::new(next.clone());
    shutdown.sign(&keys);
    client.write_all(&shutdown.encode_frame().unwrap()).unwrap();
    let acknowledgement =
        ProtectedCredentialEnrollmentShutdownAckV3::decode_frame(&read_frame(&mut client)).unwrap();
    acknowledgement.verify_exact(&next, &keys).unwrap();
    assert!(acknowledgement.graceful());
    server.join().unwrap().unwrap();
}

#[test]
fn v3_enrollment_rejects_session_rotation_until_terminal() {
    assert!(!enrollment_transcript_allows_rotation(true, false));
    assert!(enrollment_transcript_allows_rotation(true, true));
    assert!(enrollment_transcript_allows_rotation(false, false));
}
