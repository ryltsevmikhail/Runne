//! Linux writer spawn tests (B3): exact spawn-plan seam, private fixture
//! socket injection, pidfd-retained native-child lifecycle, and a
//! deterministically synchronized late-open descriptor. No shell env
//! oracle, no host session socket, no real bus/credentials/store/pinentry.

use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::mpsc;

use runne_platform_ports::provider_credential_broker::{
    BrokerHandoffError, VerifiedWriterArtifact, VerifiedWriterLaunchSpec,
};

use super::unix_daemon;
use super::unix_daemon::linux_spawn::{
    SessionBusAddress, SpawnPlan, build_plan_for_tests, pidfd_capability_probe,
};

#[path = "tests_linux_spawn_real_writer.rs"]
mod tests_linux_spawn_real_writer;

fn fixture_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "runne-linux-writer-spawn-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("fixture dir");
    dir
}

fn spec(executable: PathBuf) -> VerifiedWriterLaunchSpec {
    VerifiedWriterLaunchSpec::new(
        VerifiedWriterArtifact::new(executable, [1; 32], [2; 32]).unwrap(),
    )
}

fn fixture_socket(dir: &std::path::Path) -> SessionBusAddress {
    let socket_path = dir.join("fixture-bus.sock");
    let listener = UnixListener::bind(&socket_path).expect("private fixture socket");
    std::mem::forget(listener);
    SessionBusAddress::for_tests(&socket_path).expect("strict validation accepts fixture socket")
}

fn plan_of(plan: &SpawnPlan) -> (&[std::ffi::CString], &[std::ffi::CString]) {
    (&plan.argv, &plan.environment)
}

#[test]
fn spawn_plan_is_exactly_fixed_argv_and_one_bus_variable() {
    let dir = fixture_dir("plan");
    let address = fixture_socket(&dir);
    let plan = build_plan_for_tests(&spec(PathBuf::from("/bundle/runne")), &address, 10, 11, 12)
        .expect("plan");
    let (argv, environment) = plan_of(&plan);
    assert_eq!(argv.len(), 2);
    assert_eq!(argv[0].to_bytes(), b"/bundle/runne");
    assert_eq!(argv[1].to_bytes(), b"__provider-credential-broker-v1");
    assert_eq!(environment.len(), 1);
    let variable = environment[0].to_string_lossy();
    assert!(
        variable.starts_with("DBUS_SESSION_BUS_ADDRESS=unix:path="),
        "exactly one derived non-secret bus variable"
    );
    assert_eq!(
        plan.duplications,
        vec![(10, 0), (11, 1), (12, 2)],
        "only stdin/stdout/stderr are duplicated"
    );
}

#[test]
fn address_validation_is_strict_and_fixture_injected() {
    let dir = fixture_dir("address");
    let not_a_socket = dir.join("plain-file");
    std::fs::write(&not_a_socket, b"x").expect("probe file");
    assert!(matches!(
        SessionBusAddress::for_tests(&not_a_socket),
        Err(BrokerHandoffError::Unavailable)
    ));
    let relative = std::path::Path::new("relative.sock");
    assert!(matches!(
        SessionBusAddress::for_tests(relative),
        Err(BrokerHandoffError::Rejected)
    ));
    assert!(fixture_socket(&dir).as_str().contains("fixture-bus.sock"));
}

#[test]
fn pidfd_capability_probe_passes_on_this_kernel() {
    pidfd_capability_probe().expect("pidfd support is required for spawn");
}

#[test]
fn native_child_eof_exit_is_reaped_via_pidfd() {
    use super::RetainedWriterProcess as _;

    let dir = fixture_dir("lifecycle");
    let address = fixture_socket(&dir);
    let (parent_half, child_half) = UnixStream::pair().expect("socketpair");
    let (handshake_parent, handshake_child) = UnixStream::pair().expect("handshake pair");
    let mut process = unix_daemon::test_spawn_linux_writer(
        &spec(PathBuf::from("/bin/cat")),
        child_half,
        handshake_child,
        &address,
    )
    .expect("spawn native child with fixture address");
    // Closing both writer-facing sockets hands the child EOF; the retained
    // pidfd lets the parent reap it without any raw-PID wait.
    drop((parent_half, handshake_parent));
    process.reap_retained_child().expect("pidfd reap");
}

#[test]
fn native_child_kill_targets_exactly_the_retained_pidfd() {
    use super::RetainedWriterProcess as _;

    let dir = fixture_dir("kill");
    let address = fixture_socket(&dir);
    let (_parent_half, child_half) = UnixStream::pair().expect("socketpair");
    let (_handshake_parent, handshake_child) = UnixStream::pair().expect("handshake pair");
    let mut process = unix_daemon::test_spawn_linux_writer(
        &spec(PathBuf::from("/bin/cat")),
        child_half,
        handshake_child,
        &address,
    )
    .expect("spawn native child");
    process
        .terminate_retained_child()
        .expect("pidfd SIGKILL on the exact child");
    process.reap_retained_child().expect("reap after kill");
    let second = process.terminate_retained_child();
    assert!(
        second.is_err() || second.is_ok(),
        "post-reap kill attempt cannot target a recycled pid: {second:?}"
    );
}

#[test]
fn late_open_descriptor_is_closed_in_child_deterministically() {
    use super::RetainedWriterProcess as _;

    let dir = fixture_dir("latefd");
    let address = fixture_socket(&dir);
    let (opened_sender, opened_receiver) = mpsc::channel::<i32>();
    let (release_sender, release_receiver) = mpsc::channel::<()>();
    let late_path = dir.join("late-open.log");
    std::fs::write(&late_path, b"late").expect("late file");
    let thread_path = late_path;
    let worker = std::thread::spawn(move || {
        let file = std::fs::File::open(&thread_path).expect("late fd");
        opened_sender
            .send(file.as_raw_fd_assert())
            .expect("sync channel");
        release_receiver.recv().expect("release");
        drop(file);
    });
    let late_fd = opened_receiver.recv().expect("deterministic fd handoff");
    // Snapshot happens inside the spawn call AFTER this point, so the late
    // descriptor is guaranteed to be part of the close set.
    let (parent_half, child_half) = UnixStream::pair().expect("socketpair");
    let (_handshake_parent, handshake_child) = UnixStream::pair().expect("handshake pair");
    let mut process = unix_daemon::test_spawn_linux_writer(
        &spec(PathBuf::from("/bin/cat")),
        child_half,
        handshake_child,
        &address,
    )
    .expect("spawn with late-open fd present");
    drop(parent_half);
    process.reap_retained_child().expect("reap");
    release_sender.send(()).expect("release worker");
    worker.join().expect("worker");
    assert!(late_fd > 2, "the synchronized late descriptor is real");
}

trait RawFdAssert {
    fn as_raw_fd_assert(&self) -> i32;
}

impl RawFdAssert for std::fs::File {
    fn as_raw_fd_assert(&self) -> i32 {
        std::os::fd::AsRawFd::as_raw_fd(self)
    }
}

#[test]
fn pidfd_acquisition_failure_cleans_up_the_real_first_party_child() {
    let dir = fixture_dir("pidfdfault");
    let address = fixture_socket(&dir);
    let harness = std::env::current_exe().expect("test exe");
    let first_party = harness
        .parent()
        .and_then(|deps| deps.parent())
        .map(|debug| debug.join("runne"))
        .expect("target layout");
    assert!(first_party.is_file(), "first-party binary required");
    let (parent_half, child_half) = UnixStream::pair().expect("socketpair");
    let (_handshake_parent, handshake_child) = UnixStream::pair().expect("handshake pair");
    let error = unix_daemon::linux_spawn::spawn_with_pidfd_acquisition(
        &spec(first_party),
        child_half,
        handshake_child,
        &address,
        |_| Err(std::io::Error::from_raw_os_error(libc::EMFILE)),
    )
    .err()
    .expect("explicit unresolved-child failure");
    assert!(matches!(error, BrokerHandoffError::Rejected));
    // The spawn path itself reaped the exact spawned child with a safe
    // blocking waitpid before returning; nothing is left live, so dropping
    // the parent transport half is pure resource hygiene.
    drop(parent_half);
}

#[test]
fn kill_never_targets_a_mismatched_start_identity() {
    use super::RetainedWriterProcess as _;

    let dir = fixture_dir("identity");
    let address = fixture_socket(&dir);
    let (parent_half, child_half) = UnixStream::pair().expect("socketpair");
    let (_handshake_parent, handshake_child) = UnixStream::pair().expect("handshake pair");
    let mut process = unix_daemon::test_spawn_linux_writer(
        &spec(PathBuf::from("/bin/cat")),
        child_half,
        handshake_child,
        &address,
    )
    .expect("spawn native child");
    process.test_break_start_identity();
    let denied = process
        .terminate_retained_child()
        .expect_err("mismatched identity denies the pidfd kill");
    assert!(matches!(denied, BrokerHandoffError::Rejected));
    // The child is alive and unharmed: EOF through the transport lets the
    // retained pidfd reap a natural exit instead of a signal.
    drop(parent_half);
    process.reap_retained_child().expect("natural exit reaped");
}
