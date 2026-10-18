//! Fault-injection provenance tests for the Linux writer spawn path: every
//! `BrokerHandoffError::Unavailable` mapping records its exact operation
//! stage and the numeric raw OS errno, the public error stays `Unavailable`,
//! and the `.expect(...)` failure witness carries the provenance instead of
//! the bare public label. Synthetic faults only preempt the mapped
//! operation — they never exhaust real host resources and never leave a
//! spawned child, because every injected stage either precedes
//! `posix_spawn` or preempts that syscall before it runs.

use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;

use runne_platform_ports::provider_credential_broker::{
    BrokerHandoffError, VerifiedWriterArtifact, VerifiedWriterLaunchSpec,
};

use super::UnixRetainedWriterProcess;
use super::unix_daemon::linux_spawn::{
    SessionBusAddress, SpawnOperation, TestSpawnFailure, spawn_with_injected_fault_for_tests,
};

/// Every instrumented `Unavailable` mapping of the parent-side sequence.
const INSTRUMENTED_STAGES: [SpawnOperation; 14] = [
    SpawnOperation::PidfdCapabilityProbe,
    SpawnOperation::DuplicateControl,
    SpawnOperation::DuplicateHandshake,
    SpawnOperation::OpenNullWritable,
    SpawnOperation::DuplicateNullWritable,
    SpawnOperation::OpenNullReadable,
    SpawnOperation::SpawnActionsInit,
    SpawnOperation::SpawnActionsAddDup2,
    SpawnOperation::SpawnActionsAddClose,
    SpawnOperation::InventoryReadDir,
    SpawnOperation::InventoryAddClose,
    SpawnOperation::SpawnAttrInit,
    SpawnOperation::SpawnAttrSetFlags,
    SpawnOperation::PosixSpawn,
];

fn fixture_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rwspawn-faults-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("fixture dir");
    dir
}

/// Private fixture value owning the bus listener: ordinary RAII ownership
/// keeps the descriptor open from bind through every spawn and assertion of
/// a single test and closes it via the normal `UnixListener` `Drop` at the
/// end of that test's scope — no `mem::forget`, no process-lifetime leak.
struct FixtureBus {
    _listener: UnixListener,
    address: SessionBusAddress,
}

impl FixtureBus {
    fn bind(dir: &std::path::Path) -> Self {
        let socket_path = dir.join("fixture-bus.sock");
        let listener = UnixListener::bind(&socket_path).expect("private fixture socket");
        let address = SessionBusAddress::for_tests(&socket_path)
            .expect("strict validation accepts fixture socket");
        Self {
            _listener: listener,
            address,
        }
    }

    fn address(&self) -> &SessionBusAddress {
        &self.address
    }
}

fn cat_spec() -> VerifiedWriterLaunchSpec {
    VerifiedWriterLaunchSpec::new(
        VerifiedWriterArtifact::new(PathBuf::from("/bin/cat"), [1; 32], [2; 32]).unwrap(),
    )
}

fn faulted_spawn(
    spec: &VerifiedWriterLaunchSpec,
    address: &SessionBusAddress,
    target: SpawnOperation,
) -> Result<UnixRetainedWriterProcess, TestSpawnFailure> {
    let (_parent_half, child_half) = UnixStream::pair().expect("socketpair");
    let (_handshake_parent, handshake_child) = UnixStream::pair().expect("handshake pair");
    spawn_with_injected_fault_for_tests(
        spec,
        child_half,
        handshake_child,
        address,
        move |operation| (operation == target).then_some(libc::EMFILE),
    )
}

#[test]
fn every_unavailable_mapping_records_its_stage_and_os_errno() {
    let dir = fixture_dir("stages");
    let bus = FixtureBus::bind(&dir);
    let spec = cat_spec();
    for stage in INSTRUMENTED_STAGES {
        let failure = faulted_spawn(&spec, bus.address(), stage)
            .err()
            .unwrap_or_else(|| panic!("stage {stage:?} must fail when faulted"));
        assert_eq!(
            failure.public_error(),
            BrokerHandoffError::Unavailable,
            "public contract stays Unavailable at {stage:?}"
        );
        assert_eq!(
            failure.operation(),
            Some(stage),
            "exact stage provenance at {stage:?}"
        );
        assert_eq!(
            failure.os_errno(),
            Some(libc::EMFILE),
            "errno provenance at {stage:?}"
        );
        assert_eq!(
            format!("{failure:?}"),
            format!(
                "public=Unavailable operation={stage:?} os_errno={}",
                libc::EMFILE
            ),
            "failure witness carries provenance, not just the public label"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn faulted_spawn_drops_the_consumed_socket_ends_without_a_child() {
    use std::io::Read as _;

    let dir = fixture_dir("fds");
    let bus = FixtureBus::bind(&dir);
    // Deepest preemptible stage: every parent-side resource is opened and
    // the fault fires immediately before the posix_spawn syscall itself, so
    // no child ever exists while all consumed descriptors must be released
    // by the failing return.
    let (mut parent_half, child_half) = UnixStream::pair().expect("socketpair");
    let (mut handshake_parent, handshake_child) = UnixStream::pair().expect("handshake pair");
    let failure = spawn_with_injected_fault_for_tests(
        &cat_spec(),
        child_half,
        handshake_child,
        bus.address(),
        |operation| (operation == SpawnOperation::PosixSpawn).then_some(libc::EMFILE),
    )
    .err()
    .expect("faulted spawn fails closed");
    assert_eq!(failure.public_error(), BrokerHandoffError::Unavailable);
    let mut buffer = [0u8; 1];
    assert_eq!(
        parent_half.read(&mut buffer).ok(),
        Some(0),
        "control end released"
    );
    assert_eq!(
        handshake_parent.read(&mut buffer).ok(),
        Some(0),
        "handshake end released"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn os_errno_provenance_distinguishes_os_errors_from_code_errors() {
    let os_failure = TestSpawnFailure::from_error(
        SpawnOperation::PosixSpawn,
        &std::io::Error::from_raw_os_error(libc::EMFILE),
    );
    assert_eq!(os_failure.os_errno(), Some(libc::EMFILE));
    let nix_failure = TestSpawnFailure::from_error(
        SpawnOperation::SpawnActionsInit,
        &nix::Error::from_raw(libc::ENOMEM),
    );
    assert_eq!(nix_failure.os_errno(), Some(libc::ENOMEM));
    let rustix_failure = TestSpawnFailure::from_error(
        SpawnOperation::DuplicateControl,
        &rustix::io::Errno::from_raw_os_error(libc::EAGAIN),
    );
    assert_eq!(rustix_failure.os_errno(), Some(libc::EAGAIN));
    let code_failure = TestSpawnFailure::from_error(
        SpawnOperation::InventoryReadDir,
        &std::io::Error::other("code-level error"),
    );
    assert_eq!(code_failure.os_errno(), None);
    assert_eq!(
        format!("{code_failure:?}"),
        "public=Unavailable operation=InventoryReadDir os_errno=unavailable",
        "missing errno is recorded as unavailable, never fabricated"
    );
}
