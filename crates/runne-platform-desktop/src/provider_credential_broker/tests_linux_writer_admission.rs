//! Linux writer admission tests (T2 process-fact part): the REAL first-party
//! runne binary is spawned through the production spawn profile with a
//! private fixture socket; admission binds it to its pinned image digest and
//! retained start identity, and denies wrong images and drifted identities.
//! Ticket one-use/TTL/replay live in the daemon registry (covered elsewhere).

use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use runne_platform_ports::provider_credential_broker::{
    BrokerHandoffError, VerifiedWriterArtifact, VerifiedWriterLaunchSpec,
};
use sha2::{Digest as _, Sha256};

use super::unix_daemon;
use super::unix_daemon::linux_spawn::SessionBusAddress;
use crate::provider_credential_broker::linux_writer_admission;

/// A LIVE pinned child image: the first-party `runne` writer exits
/// immediately until the M6 writer loop exists, so admission process facts
/// are exercised on a real native child that stays alive on the held
/// transport. Image pinning itself is image-agnostic.
fn first_party_binary() -> PathBuf {
    PathBuf::from("/bin/cat")
}

static SOCKET_SERIAL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn fixture_socket() -> (tempdir_holder::Holder, SessionBusAddress) {
    let serial = SOCKET_SERIAL.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "runne-linux-admission-{}-{serial}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("fixture dir");
    let socket_path = dir.join("fixture-bus.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket_path).expect("socket");
    std::mem::forget(listener);
    let address = SessionBusAddress::for_tests(&socket_path).expect("validated fixture socket");
    (tempdir_holder::Holder(dir), address)
}

mod tempdir_holder {
    use std::path::PathBuf;
    pub struct Holder(pub PathBuf);
    impl Drop for Holder {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

fn pinned_spec() -> VerifiedWriterLaunchSpec {
    let binary = first_party_binary();
    let digest: [u8; 32] = Sha256::digest(std::fs::read(&binary).unwrap()).into();
    VerifiedWriterLaunchSpec::new(VerifiedWriterArtifact::new(binary, digest, [3; 32]).unwrap())
}

#[test]
fn admits_the_real_first_party_child_with_matching_facts() {
    use super::RetainedWriterProcess as _;

    let (_holder, address) = fixture_socket();
    let (parent_half, child_half) = UnixStream::pair().expect("socketpair");
    let (_handshake_parent, handshake_child) = UnixStream::pair().expect("handshake pair");
    let mut process =
        unix_daemon::test_spawn_linux_writer(&pinned_spec(), child_half, handshake_child, &address)
            .expect("spawn first-party child");
    let admission = linux_writer_admission::admit_linux_writer(&process, &pinned_spec())
        .expect("matching image and identity admit");
    assert_eq!(
        admission.image_digest(),
        pinned_spec().artifact().image_digest()
    );
    assert_eq!(
        admission.start_identity(),
        process.retained_start_identity()
    );
    assert_eq!(admission.pid(), process.retained_pid());
    drop(parent_half);
    process.reap_retained_child().expect("reap");
}

#[test]
fn denies_a_wrong_pinned_image_digest() {
    use super::RetainedWriterProcess as _;

    let (_holder, address) = fixture_socket();
    let (parent_half, child_half) = UnixStream::pair().expect("socketpair");
    let (_handshake_parent, handshake_child) = UnixStream::pair().expect("handshake pair");
    let binary = first_party_binary();
    let wrong = VerifiedWriterLaunchSpec::new(
        VerifiedWriterArtifact::new(binary, [9; 32], [3; 32]).unwrap(),
    );
    let mut process =
        unix_daemon::test_spawn_linux_writer(&wrong, child_half, handshake_child, &address)
            .expect("spawn first-party child");
    let denied = linux_writer_admission::admit_linux_writer(&process, &wrong)
        .err()
        .expect("wrong image digest denies");
    assert!(matches!(denied, BrokerHandoffError::Rejected));
    drop(parent_half);
    process.reap_retained_child().expect("reap");
}

#[test]
fn denies_a_drifted_start_identity() {
    use super::RetainedWriterProcess as _;

    let (_holder, address) = fixture_socket();
    let (parent_half, child_half) = UnixStream::pair().expect("socketpair");
    let (_handshake_parent, handshake_child) = UnixStream::pair().expect("handshake pair");
    let mut process =
        unix_daemon::test_spawn_linux_writer(&pinned_spec(), child_half, handshake_child, &address)
            .expect("spawn first-party child");
    process.test_break_start_identity();
    let denied = linux_writer_admission::admit_linux_writer(&process, &pinned_spec())
        .err()
        .expect("identity drift denies");
    assert!(matches!(denied, BrokerHandoffError::Rejected));
    drop(parent_half);
    process.reap_retained_child().expect("reap");
}

#[test]
fn denies_a_missing_pinned_image() {
    use super::RetainedWriterProcess as _;

    let (_holder, address) = fixture_socket();
    let (parent_half, child_half) = UnixStream::pair().expect("socketpair");
    let (_handshake_parent, handshake_child) = UnixStream::pair().expect("handshake pair");
    let mut process =
        unix_daemon::test_spawn_linux_writer(&pinned_spec(), child_half, handshake_child, &address)
            .expect("spawn first-party child");
    let missing = VerifiedWriterLaunchSpec::new(
        VerifiedWriterArtifact::new(
            std::path::PathBuf::from("/nonexistent/runne-image"),
            [1; 32],
            [3; 32],
        )
        .unwrap(),
    );
    let denied = linux_writer_admission::admit_linux_writer(&process, &missing)
        .err()
        .expect("missing image denies");
    assert!(matches!(denied, BrokerHandoffError::Rejected));
    drop(parent_half);
    process.reap_retained_child().expect("reap");
}
