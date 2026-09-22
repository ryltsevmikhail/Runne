use std::os::unix::net::UnixStream;
use std::sync::Arc;

use runne_api::{
    ActivationDispositionV1, CredentialBrokerTransferAuthenticator, LaunchSecret,
    ProtectedCredentialEnrollmentLaunchBindingV1, ProtectedCredentialEnrollmentLaunchRequestV3,
    ProtectedCredentialEnrollmentOwnedLaunchV3, ProtectedCredentialEnrollmentPreludeV2,
    ProtectedCredentialEnrollmentPrepareV2, ProtectedLaunchRequestV1, ProtectedOwnedLaunchV2,
    ProviderActivationBindingV1,
};

use super::enrollment_control_exchange::run_enrollment_control_exchange_with;
use super::enrollment_control_transition_fixture::{
    CountedGenerationStore, composition, executable, id, prepare_and_owned, profile,
    protected_service, v2_launch,
};

fn client_transcript(
    client: UnixStream,
    prepare: &ProtectedCredentialEnrollmentPrepareV2,
    keys: &runne_api::ProtectedActivationKeys,
    owned: &ProtectedOwnedLaunchV2,
    provider: &ProviderActivationBindingV1,
) -> Result<ProtectedCredentialEnrollmentOwnedLaunchV3, String> {
    let mut client = super::ProtectedActivationChannel::new(client).unwrap();
    // In production the entered control loop reads and MAC-verifies the exact
    // prepare frame before the exchange starts; the transcript binds its digest.
    let _ = prepare;
    let frame = client.read_control_frame().unwrap();
    let signed_prelude = ProtectedCredentialEnrollmentPreludeV2::decode_frame(&frame).unwrap();
    signed_prelude
        .verify_exact_at(prepare, owned, 0, 1_000, keys)
        .unwrap();
    let prelude = signed_prelude.prelude().clone();
    let commitment = CredentialBrokerTransferAuthenticator::from_protected_activation(keys)
        .enrollment_launch_commitment(&prelude);
    let constructor = match (prelude.platform(), prelude.architecture()) {
        (1, 1) => ProtectedCredentialEnrollmentLaunchBindingV1::macos_apple_silicon,
        (2, 2) => ProtectedCredentialEnrollmentLaunchBindingV1::linux_arm64,
        (2, 3) => ProtectedCredentialEnrollmentLaunchBindingV1::linux_x86_64,
        _ => panic!("unsupported target"),
    };
    let binding = constructor([6; 32], [7; 32], [8; 32], [9; 32], 1, commitment).unwrap();
    let request = ProtectedLaunchRequestV1::new(
        id(1),
        id(2),
        LaunchSecret::from_bytes([3; 32]).unwrap(),
        1_000,
        20_000,
        "local-owner",
        profile(),
        executable(),
        "/tmp/runtime".into(),
        ActivationDispositionV1::Existing(Box::new(
            owned.compatibility_owned_launch().stable().clone(),
        )),
    )
    .unwrap();
    let v3 = ProtectedCredentialEnrollmentLaunchRequestV3::new(request, provider.clone(), binding)
        .unwrap();
    client
        .write_control_frame(&v3.encode_frame().unwrap())
        .unwrap();
    let frame = match client.read_control_frame() {
        Ok(frame) => frame,
        Err(error) => return Err(format!("ready read failed: {error:?}")),
    };
    let ready = runne_api::ProtectedCredentialEnrollmentReadyV3::decode_frame(&frame).unwrap();
    let v3_keys = v3.derive_keys();
    ready.verify_exact(&v3, &v3_keys).unwrap();
    assert_eq!(ready.launch_generation(), 5);
    Ok(ready.owned_launch())
}

#[test]
fn same_process_control_transition_admits_exact_v3_and_rotates_to_reserved_generation() {
    let (original, owned, keys, provider) = v2_launch();
    let prepare = prepare_and_owned(&owned, &keys);
    let store = CountedGenerationStore::starting_at(5);
    let (sessions, current) = protected_service(&store);
    let (client, daemon) = UnixStream::pair().unwrap();
    let mut channel = super::ProtectedActivationChannel::new(daemon).unwrap();
    let clock: Arc<dyn Fn() -> std::time::Duration + Send + Sync> =
        Arc::new(|| std::time::Duration::ZERO);
    let transition_composition = composition(&original);

    std::thread::scope(|scope| {
        let daemon_thread = scope.spawn(|| {
            run_enrollment_control_exchange_with(
                &mut channel,
                &prepare,
                &keys,
                &owned,
                &transition_composition,
                &sessions,
                &clock,
                |_, _, _| true,
                |input, request, channel| {
                    super::enrollment_transition_v2_v3::transition_with(
                        input,
                        request,
                        |_, _| true,
                        channel,
                    )
                },
            )
        });
        let _ = client.set_read_timeout(Some(std::time::Duration::from_secs(3)));
        match client_transcript(client, &prepare, &keys, &owned, &provider) {
            Ok(owned_launch) => {
                let outcome = daemon_thread.join().unwrap().unwrap();
                let (_v3_keys, v3_owned_launch, _rendezvous, _installed) = outcome.into_parts();
                assert_eq!(
                    owned_launch.launch_generation(),
                    v3_owned_launch.launch_generation()
                );
            }
            Err(client_error) => {
                let daemon_result = daemon_thread
                    .join()
                    .unwrap_or_else(|panic| panic!("daemon thread panicked: {panic:?}"));
                let daemon_note = match &daemon_result {
                    Ok(_) => "Ok".to_string(),
                    Err(error) => format!("{error:?}"),
                };
                panic!("client failed: {client_error:?}; daemon result: {daemon_note}");
            }
        }
    });
    let rotated = sessions.lock().unwrap().current_binding().clone();
    assert_eq!(rotated.ephemeral().launch_generation(), 5);
    assert_ne!(
        rotated.ephemeral().session_id(),
        current.ephemeral().session_id()
    );
    assert_eq!(rotated.stable(), current.stable());
}
