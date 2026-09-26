use super::super::{SessionBusAddress, plan};
use crate::provider_credential_broker::RetainedWriterProcess as _;
use runne_platform_ports::provider_credential_broker::{
    VerifiedWriterArtifact, VerifiedWriterLaunchSpec,
};
use std::io::{Read as _, Write as _};
use std::os::unix::{
    fs::PermissionsExt as _,
    net::{UnixListener, UnixStream},
};

#[test]
fn pair_plan_keeps_only_fd3_in_addition_to_standard_streams() {
    let dir = tempfile::tempdir().unwrap();
    let bus = dir.path().join("bus");
    let _listener = UnixListener::bind(&bus).unwrap();
    let address = SessionBusAddress::for_tests(&bus).unwrap();
    let spec = VerifiedWriterLaunchSpec::new(
        VerifiedWriterArtifact::new("/bundle/runne".into(), [1; 32], [2; 32]).unwrap(),
    );
    let plan = plan::build_plan(&spec, &address, 10, 11, 12, Some(13), None).unwrap();
    assert_eq!(plan.duplications, [(10, 0), (11, 1), (12, 2), (13, 3)]);
    assert_eq!(plan.closes, [10, 11, 12, 13]);
    assert!(plan::build_plan(&spec, &address, 10, 11, 3, Some(13), None).is_err());
    assert!(plan::build_plan(&spec, &address, 10, 11, 12, Some(3), None).is_err());
}

#[cfg(feature = "test-support")]
#[test]
fn post_delete_fixture_is_forwarded_only_from_a_private_root() {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").expect("private XDG runtime directory");
    let directory = tempfile::Builder::new()
        .prefix("runne-d1-1b-plan-")
        .tempdir_in(runtime)
        .unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let bus = directory.path().join("bus");
    let _listener = UnixListener::bind(&bus).unwrap();
    let address = SessionBusAddress::for_tests(&bus).unwrap();
    let spec = VerifiedWriterLaunchSpec::new(
        VerifiedWriterArtifact::new("/bundle/runne".into(), [1; 32], [2; 32]).unwrap(),
    );
    let plan = plan::build_plan_for_tests_with_fixture_root(
        &spec,
        &address,
        10,
        11,
        12,
        Some(directory.path()),
    )
    .unwrap();
    assert_eq!(plan.environment.len(), 2);
    assert!(plan.environment.iter().any(|entry| {
        entry
            .to_string_lossy()
            .starts_with("RUNNE_D1_1B_POST_DELETE_KILL_FIXTURE_ROOT=")
    }));

    let public_parent = tempfile::tempdir().unwrap();
    std::fs::set_permissions(public_parent.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let public_root = public_parent.path().join("fixture");
    std::fs::create_dir(&public_root).unwrap();
    assert!(
        plan::build_plan_for_tests_with_fixture_root(
            &spec,
            &address,
            10,
            11,
            12,
            Some(&public_root),
        )
        .is_err()
    );
}

#[test]
fn spawned_pair_reader_receives_pipe_bytes_and_eof_on_fd3() {
    let dir = tempfile::tempdir().unwrap();
    let executable = dir.path().join("pipe-reader");
    std::fs::write(&executable, b"#!/bin/sh\nexec /bin/cat <&3\n").unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let spec = VerifiedWriterLaunchSpec::new(
        VerifiedWriterArtifact::new(executable, [1; 32], [2; 32]).unwrap(),
    );
    let bus = dir.path().join("bus");
    let _listener = UnixListener::bind(&bus).unwrap();
    let address = SessionBusAddress::for_tests(&bus).unwrap();
    let (_control_parent, control_child) = UnixStream::pair().unwrap();
    let (mut output, startup_child) = UnixStream::pair().unwrap();
    output
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    let (reader, writer) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).unwrap();
    let reader = super::super::duplicate_above_reserved(&reader).unwrap();
    let mut child = super::super::spawn_with_secret(
        &spec,
        control_child,
        startup_child,
        &address,
        Some(reader),
        super::super::open_child_pidfd,
    )
    .unwrap();
    // Transport probe only: the fixture forwards bytes without enrollment.
    let mut writer = std::fs::File::from(writer);
    writer
        .write_all(b"sealed-envelope-transport-fixture")
        .unwrap();
    drop(writer);
    let mut received = Vec::new();
    let result = output.read_to_end(&mut received);
    if result.is_err() {
        let _ = child.terminate_retained_child();
    }
    child.reap_retained_child().unwrap();
    result.unwrap();
    assert_eq!(received, b"sealed-envelope-transport-fixture");
}

#[test]
fn prepared_pair_launch_receives_the_duplex_control_endpoint() {
    use crate::provider_credential_broker::{
        prepare_daemon_owned_writer_endpoint_handoff, send_daemon_owned_writer_endpoint,
    };
    let root = tempfile::tempdir().unwrap();
    let executable = root.path().join("control-probe");
    std::fs::write(
        &executable,
        b"#!/bin/sh\nprintf claim >&0\nexec /bin/cat <&0\n",
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let spec = VerifiedWriterLaunchSpec::new(
        VerifiedWriterArtifact::new(executable, [1; 32], [2; 32]).unwrap(),
    );
    let bus = root.path().join("bus");
    let _bus = UnixListener::bind(&bus).unwrap();
    let address = SessionBusAddress::for_tests(&bus).unwrap();
    let keys = runne_api::LaunchSecret::from_bytes([7; 32])
        .unwrap()
        .derive_keys();
    let authenticator =
        runne_api::CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let authority =
        runne_api::ProviderCredentialBrokerTransferAuthority::test_only_from_authenticator(
            authenticator.clone(),
        );
    let (sender, receiver) = UnixStream::pair().unwrap();
    let (mut daemon, endpoint) = UnixStream::pair().unwrap();
    daemon
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    let prepared =
        prepare_daemon_owned_writer_endpoint_handoff(receiver, &authenticator, [3; 32], [4; 32])
            .unwrap();
    let sender = std::thread::spawn(move || {
        send_daemon_owned_writer_endpoint(sender, endpoint, &authority, [3; 32], [4; 32])
    });
    let (mut output, startup) = UnixStream::pair().unwrap();
    output
        .set_read_timeout(Some(std::time::Duration::from_secs(2)))
        .unwrap();
    let (mut child, relay) =
        super::spawn_pair_with_address(&spec, prepared, startup, &authenticator, &address).unwrap();
    drop(relay);
    let mut claim = [0; 5];
    let claim_result = daemon.read_exact(&mut claim);
    if claim_result.is_ok() {
        daemon.write_all(b"accepted").unwrap();
    }
    daemon.shutdown(std::net::Shutdown::Write).unwrap();
    let mut echoed = Vec::new();
    let echo_result = output.read_to_end(&mut echoed);
    if claim_result.is_err() || echo_result.is_err() {
        let _ = child.terminate_retained_child();
    }
    child.reap_retained_child().unwrap();
    let transfer = sender.join().unwrap();
    claim_result.expect("writer must claim over the transferred duplex socket");
    transfer.expect("authenticated endpoint transfer");
    echo_result.unwrap();
    assert_eq!(&claim, b"claim");
    assert_eq!(&echoed, b"accepted");
}

#[test]
fn prepared_pair_denies_wrong_response_authority_before_spawn() {
    use crate::provider_credential_broker::{
        prepare_daemon_owned_writer_endpoint_handoff, send_daemon_owned_writer_endpoint,
    };
    let keys = runne_api::LaunchSecret::from_bytes([7; 32])
        .unwrap()
        .derive_keys();
    let correct =
        runne_api::CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let other_keys = runne_api::LaunchSecret::from_bytes([8; 32])
        .unwrap()
        .derive_keys();
    let wrong =
        runne_api::CredentialBrokerTransferAuthenticator::from_protected_activation(&other_keys);
    let authority =
        runne_api::ProviderCredentialBrokerTransferAuthority::test_only_from_authenticator(
            correct.clone(),
        );
    let (sender, receiver) = UnixStream::pair().unwrap();
    let (_daemon, endpoint) = UnixStream::pair().unwrap();
    let prepared =
        prepare_daemon_owned_writer_endpoint_handoff(receiver, &correct, [3; 32], [4; 32]).unwrap();
    let sender = std::thread::spawn(move || {
        send_daemon_owned_writer_endpoint(sender, endpoint, &authority, [3; 32], [4; 32])
    });
    assert!(prepared.into_linux_pair_spawn_parts(&wrong).is_err());
    sender.join().unwrap().unwrap();
}
