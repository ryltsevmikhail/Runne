#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::io::{Read as _, Write as _};
use std::os::fd::IntoRawFd as _;

use runne_provider::CredentialSecretInputPresence;

use super::channel::{
    inspect_secret_input_at_for_test, secret_input_has_cloexec_for_test,
    secret_input_is_nonblocking_for_test,
};

#[test]
fn secret_slot_presence_check_does_not_adopt_or_read_the_pipe() {
    let (reader, writer) = rustix::pipe::pipe().expect("pipe");
    let mut writer = std::fs::File::from(writer);
    let descriptor = reader.into_raw_fd();

    let slot = inspect_secret_input_at_for_test(descriptor).expect("presence");
    assert!(matches!(
        slot.presence(),
        CredentialSecretInputPresence::Present
    ));
    writer
        .write_all(b"still-unread")
        .expect("write after probe");
    drop(writer);

    assert_eq!(descriptor, slot.descriptor_for_test());
    let mut channel = slot.adopt().expect("adopt");
    let mut actual = Vec::new();
    channel
        .read_to_end(&mut actual)
        .expect("read after adoption");
    assert_eq!(actual, b"still-unread");
    assert!(secret_input_has_cloexec_for_test(&channel));
    assert!(secret_input_is_nonblocking_for_test(&channel));
}

#[test]
fn secret_slot_adoption_rejects_non_pipe_and_write_only_descriptors_and_closes_them() {
    use std::os::unix::fs::MetadataExt as _;
    let regular = tempfile::tempfile().expect("regular file");
    let identity = regular.metadata().unwrap();
    let regular = regular.into_raw_fd();
    assert!(
        inspect_secret_input_at_for_test(regular)
            .expect("present regular")
            .adopt()
            .is_err()
    );
    // Never adopt a closed descriptor again: another test may already have
    // reused its number. Comparing identity checks closure without owning it.
    assert!(
        !std::fs::metadata(format!("/dev/fd/{regular}")).is_ok_and(|current| {
            current.dev() == identity.dev() && current.ino() == identity.ino()
        })
    );

    let (reader, writer) = rustix::pipe::pipe().expect("pipe");
    let write_only = writer.into_raw_fd();
    assert!(
        inspect_secret_input_at_for_test(write_only)
            .expect("present writer")
            .adopt()
            .is_err()
    );
    nix::fcntl::fcntl(
        &reader,
        nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
    )
    .unwrap();
    // EOF proves the rejected write end was closed; WouldBlock would mean
    // a surviving writer. No raw-descriptor re-probe can close another test's fd.
    assert_eq!(std::fs::File::from(reader).read(&mut [0]).unwrap(), 0);
}

#[test]
fn missing_secret_slot_is_reported_without_opening_any_source() {
    assert!(matches!(
        inspect_secret_input_at_for_test(i32::MAX)
            .expect("missing")
            .presence(),
        CredentialSecretInputPresence::Absent
    ));
}

#[test]
fn dropping_a_present_secret_slot_closes_the_inherited_descriptor() {
    let (reader, writer) = rustix::pipe::pipe().expect("pipe");
    let mut writer = std::fs::File::from(writer);
    let descriptor = reader.into_raw_fd();
    let slot = inspect_secret_input_at_for_test(descriptor).expect("presence");

    drop(slot);

    let error = writer.write_all(b"closed peer").expect_err("reader closed");
    assert_eq!(error.raw_os_error(), Some(libc::EPIPE));
}

#[test]
fn open_secret_pipe_without_eof_is_rejected_by_the_read_deadline() {
    let (reader, _writer_kept_open) = rustix::pipe::pipe().expect("pipe");
    let descriptor = reader.into_raw_fd();
    let slot = inspect_secret_input_at_for_test(descriptor).expect("presence");
    assert_eq!(descriptor, slot.descriptor_for_test());
    let mut channel = slot
        .adopt_with_timeout_for_test(std::time::Duration::from_millis(20))
        .expect("adopt");
    let started = std::time::Instant::now();

    assert!(super::read_sealed_pair_envelope(&mut channel).is_err());
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
}

#[test]
fn nonblocking_secret_pipe_accepts_delayed_input_before_its_deadline() {
    let (reader, writer) = rustix::pipe::pipe().expect("pipe");
    let descriptor = reader.into_raw_fd();
    let slot = inspect_secret_input_at_for_test(descriptor).expect("presence");
    let mut channel = slot
        .adopt_with_timeout_for_test(std::time::Duration::from_secs(1))
        .expect("adopt");
    let writer = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(20));
        let mut writer = std::fs::File::from(writer);
        writer.write_all(b"delayed").expect("write delayed bytes");
    });
    let mut actual = Vec::new();

    channel
        .read_to_end(&mut actual)
        .expect("read delayed bytes");
    writer.join().expect("writer thread");
    assert_eq!(actual, b"delayed");
}

#[cfg(target_os = "linux")]
#[test]
fn linux_sweep_retains_only_validated_secret_pipe_and_closes_unrelated_input() {
    let (reader, writer) = rustix::pipe::pipe().expect("secret pipe");
    let descriptor = reader.into_raw_fd();
    let slot = inspect_secret_input_at_for_test(descriptor).expect("present");
    let retained = slot
        .validated_descriptor_for_sweep()
        .expect("read-only pipe");
    let (unrelated_reader, unrelated_writer) = rustix::pipe::pipe().expect("unrelated pipe");
    let unrelated = unrelated_reader.into_raw_fd();
    super::writer_fd_sweep::close_inherited_descriptors_except(
        || Ok(vec![descriptor, unrelated]),
        retained,
    )
    .expect("sweep");
    let mut unrelated_writer = std::fs::File::from(unrelated_writer);
    assert_eq!(
        unrelated_writer
            .write_all(b"unreachable")
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EPIPE)
    );
    let mut writer = std::fs::File::from(writer);
    writer
        .write_all(b"retained-unread")
        .expect("secret pipe retained");
    drop(writer);
    let mut actual = Vec::new();
    slot.adopt()
        .expect("adopt after claim")
        .read_to_end(&mut actual)
        .unwrap();
    assert_eq!(actual, b"retained-unread");
}

#[cfg(target_os = "linux")]
#[test]
fn linux_sweep_exception_rejects_a_socket_or_write_only_pipe() {
    let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let slot = inspect_secret_input_at_for_test(socket.into_raw_fd()).unwrap();
    assert!(slot.validated_descriptor_for_sweep().is_err());
    drop(slot);
    let (_reader, writer) = rustix::pipe::pipe().unwrap();
    let slot = inspect_secret_input_at_for_test(writer.into_raw_fd()).unwrap();
    assert!(slot.validated_descriptor_for_sweep().is_err());
}
