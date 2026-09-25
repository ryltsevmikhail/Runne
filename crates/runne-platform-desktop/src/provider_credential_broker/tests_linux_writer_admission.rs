//! Linux writer admission tests (T2 process-fact part): the REAL first-party
//! runne binary is spawned through the production spawn profile with a
//! private fixture socket; admission binds it to its pinned image digest and
//! retained start identity, and denies wrong images and drifted identities.
//! Ticket one-use/TTL/replay live in the daemon registry (covered elsewhere).

use std::os::unix::fs::PermissionsExt as _;
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
#[ignore = "requires the owner Linux session environment; the real first-party child must stay alive for the live /proc admission"]
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

#[test]
fn denies_a_replaced_executable_path_after_spawn() {
    use super::RetainedWriterProcess as _;

    let (holder, address) = fixture_socket();
    let image = holder.0.join("writer-image");
    std::fs::copy("/bin/cat", &image).expect("copy fixture writer");
    let mut permissions = std::fs::metadata(&image)
        .expect("image metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&image, permissions).expect("make fixture executable");
    let digest: [u8; 32] = Sha256::digest(std::fs::read(&image).expect("read image")).into();
    let spec = VerifiedWriterLaunchSpec::new(
        VerifiedWriterArtifact::new(image.clone(), digest, [3; 32]).unwrap(),
    );
    let (parent_half, child_half) = UnixStream::pair().expect("socketpair");
    let (_handshake_parent, handshake_child) = UnixStream::pair().expect("handshake pair");
    let mut process =
        unix_daemon::test_spawn_linux_writer(&spec, child_half, handshake_child, &address)
            .expect("spawn fixture writer");

    // Keep the running process on the original inode while making its launch
    // pathname resolve to a different regular executable object.
    std::fs::rename(&image, holder.0.join("writer-image-original")).expect("move original image");
    std::fs::copy("/bin/true", &image).expect("replace image pathname");

    let denied = linux_writer_admission::admit_linux_writer(&process, &spec)
        .err()
        .expect("different pathname object denies");
    assert!(matches!(denied, BrokerHandoffError::Rejected));
    drop(parent_half);
    process.reap_retained_child().expect("reap");
}

#[test]
fn denies_a_writer_that_exits_before_admission_confirmation() {
    use super::RetainedWriterProcess as _;

    let (_holder, address) = fixture_socket();
    let spec = pinned_spec();
    let (parent_half, child_half) = UnixStream::pair().expect("socketpair");
    let (_handshake_parent, handshake_child) = UnixStream::pair().expect("handshake pair");
    let mut process =
        unix_daemon::test_spawn_linux_writer(&spec, child_half, handshake_child, &address)
            .expect("spawn fixture writer");

    let denied =
        linux_writer_admission::admit_linux_writer_with_confirmation_hook(&process, &spec, || {
            // /bin/cat exits on stdin EOF. Wait via the retained pidfd so the
            // child is known to have exited before the final admission check.
            drop(parent_half);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while process.ensure_running().is_ok() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "writer did not exit after stdin EOF"
                );
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        })
        .err()
        .expect("exited child denies final admission confirmation");
    assert!(matches!(denied, BrokerHandoffError::Rejected));
    process.reap_retained_child().expect("reap");
}

#[test]
fn denies_a_writer_that_execs_a_replacement_during_admission() {
    use super::RetainedWriterProcess as _;
    use std::os::unix::fs::MetadataExt as _;

    let (holder, address) = fixture_socket();
    let image = holder.0.join("exec-on-eof");
    let source = holder.0.join("exec-on-eof.rs");
    std::fs::write(
        &source,
        r#"use std::io::Read as _;
use std::os::unix::process::CommandExt as _;
fn main() {
    let mut input = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut input);
    let error = std::process::Command::new("/usr/bin/yes").exec();
    panic!("exec failed: {error}");
}"#,
    )
    .expect("write fixture source");
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let compiled = std::process::Command::new(rustc)
        .args(["--edition=2024", "-o"])
        .arg(&image)
        .arg(&source)
        .status()
        .expect("run rustc for exec fixture");
    assert!(compiled.success(), "exec fixture compiles");
    let digest: [u8; 32] = Sha256::digest(std::fs::read(&image).expect("read fixture")).into();
    let pinned_metadata = std::fs::metadata(&image).expect("fixture metadata");
    let spec =
        VerifiedWriterLaunchSpec::new(VerifiedWriterArtifact::new(image, digest, [3; 32]).unwrap());
    let (parent_half, child_half) = UnixStream::pair().expect("socketpair");
    let (_handshake_parent, handshake_child) = UnixStream::pair().expect("handshake pair");
    let mut process =
        unix_daemon::test_spawn_linux_writer(&spec, child_half, handshake_child, &address)
            .expect("spawn exec fixture");

    let denied =
        linux_writer_admission::admit_linux_writer_with_confirmation_hook(&process, &spec, || {
            drop(parent_half);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            loop {
                let current = std::fs::metadata(format!("/proc/{}/exe", process.test_pid()))
                    .expect("live proc exe metadata");
                if current.dev() != pinned_metadata.dev() || current.ino() != pinned_metadata.ino()
                {
                    break;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "child did not exec replacement image"
                );
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        })
        .err()
        .expect("exec replacement denies final admission confirmation");
    assert!(matches!(denied, BrokerHandoffError::Rejected));
    process
        .terminate_retained_child()
        .expect("kill replacement");
    process.reap_retained_child().expect("reap");
}
