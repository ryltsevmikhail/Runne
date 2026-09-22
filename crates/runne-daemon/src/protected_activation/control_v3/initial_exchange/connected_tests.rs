use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use ed25519_dalek::SigningKey;
use runne_native_qualification::QualificationAdmissionVerifier;

mod support;
use support::*;

mod metadata_tests;

#[test]
fn connected_valid_pair_with_extra_frame_closes_before_gcp_and_cannot_cross_session() {
    let context_key = SigningKey::from_bytes(&[7; 32]);
    let fault_key = SigningKey::from_bytes(&[9; 32]);
    let verified = Arc::new(AtomicUsize::new(0));
    let fixture = runne_platform_desktop::test_only_connected_ready_v3_enrollment_supervisor();
    let (mut supervisor, desktop_peer, keys, owned, installed) = fixture.into_parts();
    let first_session = *owned.session_id();
    let (control, database) = control();
    let (mut proxy_daemon, daemon_channel) = UnixStream::pair().unwrap();
    let daemon = spawn_daemon(
        daemon_channel,
        keys,
        owned.clone(),
        installed,
        Arc::clone(&control),
        QualificationAdmissionVerifier::test_only_from_verifying_keys(
            context_key.verifying_key(),
            fault_key.verifying_key(),
        ),
        Arc::clone(&verified),
    );
    let proxy = BoundedThread::spawn(move || {
        let mut desktop_peer = desktop_peer;
        let context =
            crate::protected_activation::enrollment_v3_tests::read_frame(&mut desktop_peer);
        let fault = crate::protected_activation::enrollment_v3_tests::read_frame(&mut desktop_peer);
        assert_eq!(&context[4..12], b"RNQCTX1\0");
        assert_eq!(&fault[4..12], b"RNQFRLY1");
        let relay = [context, fault].concat();
        let with_extra = [relay.clone(), relay.clone()].concat();
        proxy_daemon.write_all(&with_extra).unwrap();
        let initial =
            crate::protected_activation::enrollment_v3_tests::read_frame(&mut desktop_peer);
        assert_eq!(&initial[4..12], b"GCPCECTL");
        // The duplicate qualification envelope precedes the real ordinary request.
        assert_eq!(proxy_daemon.read(&mut [0; 1]).unwrap(), 0);
        relay
    });
    let begin =
        runne_platform_desktop::NativeProtectedCredentialEnrollmentBegin::new(command(), [9; 32])
            .unwrap();
    let started = Instant::now();
    assert!(
        supervisor
            .begin_protected_credential_enrollment_with_qualification(
                begin,
                Some(super::qualification_admission_tests::support::admission(
                    &context_key,
                    &fault_key,
                )),
            )
            .is_err()
    );
    assert!(started.elapsed() < TEST_TIMEOUT);
    let relay = proxy.wait("relay proxy/daemon close");
    assert!(daemon.wait("first daemon close").is_err());
    assert_eq!(
        verified.load(Ordering::SeqCst),
        2,
        "registration must complete before combined verification"
    );
    assert_zero_operations(support::relay_db(database.path()));
    let cleanup = BoundedThread::spawn(move || {
        let stopped = supervisor.stop();
        (stopped, supervisor.owns_runtime())
    });
    let (stopped, owns_runtime) = cleanup.wait("first supervisor cleanup");
    assert_eq!(
        stopped.unwrap(),
        runne_platform_desktop::BundledRuntimeStopDisposition::Forced
    );
    assert!(!owns_runtime);

    let next = runne_platform_desktop::test_only_connected_ready_v3_enrollment_supervisor();
    let (mut next_supervisor, unused_peer, next_keys, next_owned, next_installed) =
        next.into_parts();
    assert_ne!(next_owned.session_id(), &first_session);
    let (mut old_sender, next_daemon_channel) = UnixStream::pair().unwrap();
    let next_daemon = spawn_daemon(
        next_daemon_channel,
        next_keys,
        next_owned,
        next_installed,
        control,
        QualificationAdmissionVerifier::test_only_from_verifying_keys(
            context_key.verifying_key(),
            fault_key.verifying_key(),
        ),
        Arc::clone(&verified),
    );
    old_sender.write_all(&relay).unwrap();
    drop(old_sender);
    assert!(next_daemon.wait("second daemon close").is_err());
    assert_eq!(
        verified.load(Ordering::SeqCst),
        2,
        "cross-session relay verified"
    );
    assert_zero_operations(support::relay_db(database.path()));
    drop(unused_peer);
    let cleanup = BoundedThread::spawn(move || next_supervisor.stop());
    assert_eq!(
        cleanup.wait("second supervisor cleanup").unwrap(),
        runne_platform_desktop::BundledRuntimeStopDisposition::Forced
    );
}

#[test]
fn connected_absent_admission_preserves_the_canonical_legacy_first_frame() {
    let verified = Arc::new(AtomicUsize::new(0));
    let fixture = runne_platform_desktop::test_only_connected_ready_v3_enrollment_supervisor();
    let (mut supervisor, desktop_peer, keys, owned, installed) = fixture.into_parts();
    let daemon_keys = keys.clone();
    let (control, _database) = control();
    let (mut proxy_daemon, daemon_channel) = UnixStream::pair().unwrap();
    let daemon = spawn_daemon(
        daemon_channel,
        daemon_keys,
        owned,
        installed,
        control,
        QualificationAdmissionVerifier::test_only_from_verifying_keys(
            SigningKey::from_bytes(&[7; 32]).verifying_key(),
            SigningKey::from_bytes(&[9; 32]).verifying_key(),
        ),
        Arc::clone(&verified),
    );
    let proxy = BoundedThread::spawn(move || {
        let mut desktop_peer = desktop_peer;
        let first = crate::protected_activation::enrollment_v3_tests::read_frame(&mut desktop_peer);
        assert_eq!(&first[4..12], b"GCPCECTL");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .try_into()
            .unwrap();
        runne_api::ProtectedCredentialEnrollmentAuthenticator::from_protected_activation(&keys)
            .decode_authenticated_request(&first, 0, now)
            .unwrap();
        assert!(
            !runne_native_qualification::QualificationRunContextRelayCodecV1::recognizes_frame(
                &first
            )
        );
        proxy_daemon.write_all(&first).unwrap();
        first
    });
    let begin =
        runne_platform_desktop::NativeProtectedCredentialEnrollmentBegin::new(command(), [9; 32])
            .unwrap();
    assert!(
        supervisor
            .begin_protected_credential_enrollment_with_qualification(begin, None)
            .is_err()
    );
    let first = proxy.wait("absent legacy first frame");
    assert_eq!(
        u32::from_be_bytes(first[..4].try_into().unwrap()) as usize,
        first.len() - 4
    );
    assert!(daemon.wait("absent daemon close").is_err());
    assert_eq!(verified.load(Ordering::SeqCst), 1);
    let cleanup = BoundedThread::spawn(move || supervisor.stop());
    assert_eq!(
        cleanup.wait("absent supervisor cleanup").unwrap(),
        runne_platform_desktop::BundledRuntimeStopDisposition::Forced
    );
}
