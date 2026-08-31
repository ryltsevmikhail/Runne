#[cfg(target_os = "macos")]
#[test]
fn live_writer_admission_requires_exact_sec_code_path_and_handoff_binding() {
    use super::RetainedWriterProcess as _;

    let launch = super::macos_writer_admission::test_apple_launch(
        std::path::Path::new("/usr/bin/yes"),
        [7; 32],
    )
    .unwrap();
    let (transport, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let image = super::macos_writer_admission::prepare_retained_writer_image(&launch).unwrap();
    let mut process =
        super::unix_daemon_macos::spawn_macos_prepared_writer(launch.launch(), &image, transport)
            .unwrap();

    let evidence = super::macos_writer_admission::verify_live_writer(
        &process, &launch, &image, [8; 32], [9; 32], [10; 32],
    )
    .unwrap();
    assert!(evidence.matches_daemon_owned_launch(launch.launch(), [8; 32], [9; 32]));
    assert!(
        super::macos_writer_admission::verify_live_writer(
            &process, &launch, &image, [0; 32], [9; 32], [10; 32],
        )
        .is_err()
    );

    let wrong_path = super::macos_writer_admission::test_apple_launch(
        std::path::Path::new("/usr/bin/true"),
        [7; 32],
    )
    .unwrap();
    assert!(
        super::macos_writer_admission::verify_live_writer(
            &process,
            &wrong_path,
            &image,
            [8; 32],
            [9; 32],
            [10; 32],
        )
        .is_err()
    );
    let wrong_requirement =
        launch.with_test_requirement("identifier \"com.apple.false\" and anchor apple");
    assert!(
        super::macos_writer_admission::verify_live_writer(
            &process,
            &wrong_requirement,
            &image,
            [8; 32],
            [9; 32],
            [10; 32],
        )
        .is_err()
    );

    process.terminate_retained_child().unwrap();
    process.reap_retained_child().unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn prepared_handoff_retains_binding_through_live_macos_admission() {
    use runne_api::{CredentialBrokerTransferAuthenticator, LaunchSecret};

    let launch = super::macos_writer_admission::test_apple_launch(
        std::path::Path::new("/usr/bin/yes"),
        [17; 32],
    )
    .unwrap();
    let (daemon, writer) = std::os::unix::net::UnixStream::pair().unwrap();
    let (sender, receiver) = std::os::unix::net::UnixStream::pair().unwrap();
    let keys = LaunchSecret::from_bytes([18; 32]).unwrap().derive_keys();
    let sender_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let sender_authority =
        runne_api::ProviderCredentialBrokerTransferAuthority::test_only_from_authenticator(
            sender_authenticator,
        );
    let receiver_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let channel_binding = [19; 32];
    let publication_public_key = [20; 32];
    let sender_thread = std::thread::spawn(move || {
        super::send_daemon_owned_writer_endpoint(
            sender,
            writer,
            &sender_authority,
            channel_binding,
            publication_public_key,
        )
    });
    let prepared = super::prepare_daemon_owned_writer_endpoint_handoff(
        receiver,
        &receiver_authenticator,
        channel_binding,
        publication_public_key,
    )
    .unwrap();

    let verified =
        super::spawn_macos_verified_writer_from_prepared_daemon_handoff(launch, prepared).unwrap();
    sender_thread.join().unwrap().unwrap();
    assert!(verified.matches_handoff(channel_binding, publication_public_key));
    drop(verified);
    drop(daemon);
}

#[cfg(target_os = "macos")]
#[test]
fn post_spawn_path_replacement_cannot_substitute_the_executed_vnode() {
    use super::RetainedWriterProcess as _;

    let directory = tempfile::tempdir().unwrap();
    let writer = directory.path().join("writer");
    let retained_path = directory.path().join("retained-writer");
    std::fs::copy("/usr/bin/yes", &writer).unwrap();
    let launch = super::macos_writer_admission::test_apple_launch(&writer, [21; 32]).unwrap();
    let image = super::macos_writer_admission::prepare_retained_writer_image(&launch).unwrap();

    std::fs::rename(&writer, &retained_path).unwrap();
    std::fs::copy("/usr/bin/yes", &writer).unwrap();
    let (transport, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut process =
        super::unix_daemon_macos::spawn_macos_prepared_writer(launch.launch(), &image, transport)
            .unwrap();
    std::fs::remove_file(&writer).unwrap();
    std::fs::rename(&retained_path, &writer).unwrap();

    assert!(
        super::macos_writer_admission::verify_live_writer(
            &process, &launch, &image, [22; 32], [23; 32], [24; 32],
        )
        .is_err()
    );
    process.terminate_retained_child().unwrap();
    process.reap_retained_child().unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn live_macos_evidence_transfer_is_one_shot_and_release_bound() {
    use runne_api::{CredentialBrokerTransferAuthenticator, LaunchSecret};

    let launch = super::macos_writer_admission::test_apple_launch(
        std::path::Path::new("/usr/bin/yes"),
        [24; 32],
    )
    .unwrap();
    let (daemon, writer) = std::os::unix::net::UnixStream::pair().unwrap();
    let (handoff_sender, handoff_receiver) = std::os::unix::net::UnixStream::pair().unwrap();
    let keys = LaunchSecret::from_bytes([25; 32]).unwrap().derive_keys();
    let handoff_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let handoff_authority =
        runne_api::ProviderCredentialBrokerTransferAuthority::test_only_from_authenticator(
            handoff_authenticator,
        );
    let receiver_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let channel_binding = [26; 32];
    let publication_public_key = [27; 32];
    let sender_thread = std::thread::spawn(move || {
        super::send_daemon_owned_writer_endpoint(
            handoff_sender,
            writer,
            &handoff_authority,
            channel_binding,
            publication_public_key,
        )
    });
    let prepared = super::prepare_daemon_owned_writer_endpoint_handoff(
        handoff_receiver,
        &receiver_authenticator,
        channel_binding,
        publication_public_key,
    )
    .unwrap();
    let verified =
        super::spawn_macos_verified_writer_from_prepared_daemon_handoff(launch, prepared).unwrap();
    sender_thread.join().unwrap().unwrap();

    let (evidence_sender, evidence_receiver) = std::os::unix::net::UnixStream::pair().unwrap();
    let send_authenticator =
        CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let evidence_receiver_authority =
        runne_api::ProviderCredentialBrokerTransferAuthority::test_only_from_authenticator(
            CredentialBrokerTransferAuthenticator::from_protected_activation(&keys),
        );
    let receiver_thread = std::thread::spawn(move || {
        super::daemon_evidence::receive_daemon_owned_writer_measurements(
            evidence_receiver,
            evidence_receiver_authority,
            [24; 32],
            channel_binding,
            publication_public_key,
        )
    });
    let pending = verified
        .transfer_evidence_to_daemon(evidence_sender, &send_authenticator)
        .unwrap();
    let (evidence, _) = receiver_thread.join().unwrap().unwrap();
    assert!(evidence.matches_daemon_owned_release(
        [24; 32],
        channel_binding,
        publication_public_key,
    ));
    drop(pending);
    drop(daemon);
}
