use std::io::Write as _;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use super::{
    QUALIFICATION_ADMISSION_DESCRIPTOR, QualificationAdmissionHostState,
    inspect_qualification_admission_at_for_test, protected_admission_for_test,
};
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use sha2::{Digest as _, Sha256};

const FRAME: &[u8] = br#"{"schema_version":"runne/macos-xpc-dpk-fault-ticket/v1","ticket_id":"1111111111111111111111111111111111111111111111111111111111111111","selector":"kill_desktop_process","process_role":"desktop","candidate_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","release_tuple_v3_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","source_revision":"cccccccccccccccccccccccccccccccccccccccc","workflow_run_id":"run-42","namespace_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","issued_at":1800000000,"expires_at":1800000600,"nonce":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI","signature":{"algorithm":"ed25519","key_id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","value":"MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMw"}}"#;
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn admission_bundle() -> Vec<u8> {
    let ticket_sha256 = hex::encode(Sha256::digest(FRAME));
    let context = format!(
        "{{\"schema_version\":\"runne/macos-xpc-dpk-run-context/v1\",\"context_id\":\"{}\",\"scenario_id\":\"macos-xpc-dpk-v1\",\"selector\":\"kill_desktop_process\",\"process_role\":\"desktop\",\"candidate_sha256\":\"{}\",\"release_tuple_v3_sha256\":\"{}\",\"source_revision\":\"{}\",\"workflow_run_id\":\"run-42\",\"namespace_sha256\":\"{}\",\"ticket_sha256\":\"{ticket_sha256}\",\"issued_at\":1800000000,\"expires_at\":1800000300,\"nonce\":\"REREREREREREREREREREREREREREREREREREREREREQ\",\"signature\":{{\"algorithm\":\"ed25519\",\"key_id\":\"{}\",\"value\":\"MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMw\"}}}}",
        "33".repeat(32), "aa".repeat(32), "bb".repeat(32), "cc".repeat(20),
        "dd".repeat(32), "ee".repeat(32),
    ).into_bytes();
    let mut bundle = Vec::with_capacity(17 + context.len() + FRAME.len());
    bundle.extend_from_slice(b"RNQADM1\0");
    bundle.push(1);
    bundle.extend_from_slice(&u32::try_from(context.len()).unwrap().to_be_bytes());
    bundle.extend_from_slice(&u32::try_from(FRAME.len()).unwrap().to_be_bytes());
    bundle.extend_from_slice(&context);
    bundle.extend_from_slice(FRAME);
    bundle
}

fn pipe_with(bytes: &[u8], keep_open: bool) -> (i32, Option<std::fs::File>) {
    let (reader, writer) = nix::unistd::pipe().expect("pipe");
    let mut writer = std::fs::File::from(writer);
    writer.write_all(bytes).expect("write fixture");
    let writer = keep_open.then_some(writer);
    (high_descriptor(reader), writer)
}

fn high_descriptor(descriptor: impl AsFd) -> i32 {
    fcntl(&descriptor, FcntlArg::F_DUPFD_CLOEXEC(512)).expect("high descriptor")
}

fn lock_tests() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn descriptor_is_closed(descriptor: i32) -> bool {
    std::fs::metadata(format!("/dev/fd/{descriptor}")).is_err()
}

#[test]
fn missing_admission_is_inert_and_fixed_slot_does_not_alias_secret_fd() {
    let _guard = lock_tests();
    assert_eq!(QUALIFICATION_ADMISSION_DESCRIPTOR, 198);
    assert_ne!(QUALIFICATION_ADMISSION_DESCRIPTOR, 3);
    let slot = inspect_qualification_admission_at_for_test(i32::MAX).expect("inspect absent");
    assert!(!slot.is_present());
    let host =
        QualificationAdmissionHostState::admit_for_test(slot, None, Duration::from_millis(20))
            .expect("absent is inert");
    assert!(!host.has_pending_for_test());
}

#[test]
fn inspection_does_not_read_and_success_closes_inherited_pipe() {
    let _guard = lock_tests();
    let (reader, writer) = nix::unistd::pipe().expect("pipe");
    let mut writer = std::fs::File::from(writer);
    let descriptor = high_descriptor(reader);
    let slot = inspect_qualification_admission_at_for_test(descriptor).expect("inspect present");
    writer
        .write_all(&admission_bundle())
        .expect("write after inspection");
    drop(writer);
    let host = QualificationAdmissionHostState::admit_for_test(
        slot,
        Some(protected_admission_for_test()),
        Duration::from_secs(1),
    )
    .expect("admit frame");
    assert!(descriptor_is_closed(descriptor));
    assert!(host.has_pending_for_test());
}

#[test]
fn pending_host_slot_is_consumed_once() {
    let _guard = lock_tests();
    let bundle = admission_bundle();
    let (descriptor, _writer) = pipe_with(&bundle, false);
    let slot = inspect_qualification_admission_at_for_test(descriptor).expect("present");
    let host = QualificationAdmissionHostState::admit_for_test(
        slot,
        Some(protected_admission_for_test()),
        Duration::from_secs(1),
    )
    .expect("pending host");
    assert!(host.take_pending_for_relay().unwrap().is_some());
    assert!(host.take_pending_for_relay().unwrap().is_none());
}

#[test]
fn pending_host_slot_moves_to_relay_only_once() {
    let _guard = lock_tests();
    let bundle = admission_bundle();
    let (descriptor, _writer) = pipe_with(&bundle, false);
    let slot = inspect_qualification_admission_at_for_test(descriptor).expect("present");
    let host = QualificationAdmissionHostState::admit_for_test(
        slot,
        Some(protected_admission_for_test()),
        Duration::from_secs(1),
    )
    .expect("pending host");
    assert!(host.take_pending_for_relay().unwrap().is_some());
    assert!(host.take_pending_for_relay().unwrap().is_none());
}

#[test]
fn drop_and_provenance_failure_close_inherited_descriptor() {
    let _guard = lock_tests();
    let (dropped, _writer) = pipe_with(b"", true);
    drop(inspect_qualification_admission_at_for_test(dropped).expect("present"));
    assert!(descriptor_is_closed(dropped));

    let bundle = admission_bundle();
    let (rejected, _writer) = pipe_with(&bundle, false);
    let slot = inspect_qualification_admission_at_for_test(rejected).expect("present");
    assert!(
        QualificationAdmissionHostState::admit_for_test(slot, None, Duration::from_secs(1))
            .is_err()
    );
    assert!(descriptor_is_closed(rejected));
}

#[test]
fn adopted_channel_is_cloexec_nonblocking_and_single_use() {
    let _guard = lock_tests();
    let bundle = admission_bundle();
    let (descriptor, _writer) = pipe_with(&bundle, false);
    let slot = inspect_qualification_admission_at_for_test(descriptor).expect("present");
    let channel = slot
        .adopt_channel_for_test(Duration::from_secs(1))
        .expect("adopt channel");
    let fd_flags = FdFlag::from_bits_retain(fcntl(&channel.file, FcntlArg::F_GETFD).unwrap());
    let status = OFlag::from_bits_retain(fcntl(&channel.file, FcntlArg::F_GETFL).unwrap());
    assert!(fd_flags.contains(FdFlag::FD_CLOEXEC));
    assert!(status.contains(OFlag::O_NONBLOCK));
    assert!(descriptor_is_closed(descriptor));
}

#[test]
fn rejects_non_channels_and_write_only_pipe_and_closes_them() {
    let _guard = lock_tests();
    let directory = tempfile::tempdir().expect("directory");
    let cases = [
        high_descriptor(tempfile::tempfile().expect("regular")),
        high_descriptor(std::fs::File::open(directory.path()).unwrap()),
        high_descriptor(std::fs::File::open("/dev/null").unwrap()),
        high_descriptor(nix::unistd::pipe().expect("pipe").1),
    ];
    for descriptor in cases {
        let slot = inspect_qualification_admission_at_for_test(descriptor).expect("present");
        assert!(
            QualificationAdmissionHostState::admit_for_test(
                slot,
                Some(protected_admission_for_test()),
                Duration::from_millis(20),
            )
            .is_err()
        );
        assert!(descriptor_is_closed(descriptor));
    }
}

#[test]
fn connected_socket_is_accepted_but_listener_is_rejected() {
    let _guard = lock_tests();
    let (reader, mut writer) = UnixStream::pair().expect("socket pair");
    let descriptor = high_descriptor(reader);
    writer.write_all(&admission_bundle()).expect("write frame");
    writer.shutdown(std::net::Shutdown::Write).expect("eof");
    let slot = inspect_qualification_admission_at_for_test(descriptor).expect("present");
    assert!(
        QualificationAdmissionHostState::admit_for_test(
            slot,
            Some(protected_admission_for_test()),
            Duration::from_secs(1),
        )
        .unwrap()
        .has_pending_for_test()
    );

    let directory = tempfile::tempdir().expect("socket directory");
    let listener = std::os::unix::net::UnixListener::bind(directory.path().join("ticket.sock"))
        .expect("listener");
    let descriptor = high_descriptor(listener);
    let slot = inspect_qualification_admission_at_for_test(descriptor).expect("present");
    assert!(
        QualificationAdmissionHostState::admit_for_test(
            slot,
            Some(protected_admission_for_test()),
            Duration::from_millis(20),
        )
        .is_err()
    );
    assert!(descriptor_is_closed(descriptor));
}

#[test]
fn empty_oversized_trailing_and_malformed_frames_are_rejected() {
    let _guard = lock_tests();
    let valid = admission_bundle();
    let oversized = vec![b'x'; runne_native_qualification::MAX_ADMISSION_BUNDLE_BYTES + 1];
    let trailing = [valid.as_slice(), b"x"].concat();
    for bytes in [
        b"".as_slice(),
        oversized.as_slice(),
        trailing.as_slice(),
        FRAME,
        b"{}",
    ] {
        let (descriptor, _writer) = pipe_with(bytes, false);
        let slot = inspect_qualification_admission_at_for_test(descriptor).expect("present");
        assert!(
            QualificationAdmissionHostState::admit_for_test(
                slot,
                Some(protected_admission_for_test()),
                Duration::from_secs(1),
            )
            .is_err()
        );
        assert!(descriptor_is_closed(descriptor));
    }
}

#[test]
fn partial_and_would_block_inputs_fail_at_one_bounded_deadline() {
    let _guard = lock_tests();
    let bundle = admission_bundle();
    for bytes in [bundle.as_slice(), b""] {
        let (descriptor, _writer_kept_open) = pipe_with(bytes, true);
        let slot = inspect_qualification_admission_at_for_test(descriptor).expect("present");
        let started = std::time::Instant::now();
        assert!(
            QualificationAdmissionHostState::admit_for_test(
                slot,
                Some(protected_admission_for_test()),
                Duration::from_millis(20),
            )
            .is_err()
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(descriptor_is_closed(descriptor));
    }
}

#[test]
fn descriptor_invalidated_after_inspection_is_rejected() {
    let _guard = lock_tests();
    let bundle = admission_bundle();
    let (descriptor, _writer) = pipe_with(&bundle, false);
    let slot = inspect_qualification_admission_at_for_test(descriptor).expect("present");
    nix::unistd::close(descriptor).expect("invalidate");
    assert!(
        QualificationAdmissionHostState::admit_for_test(
            slot,
            Some(protected_admission_for_test()),
            Duration::from_millis(20),
        )
        .is_err()
    );
}
