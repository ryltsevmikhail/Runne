//! Test-only spawn entry points for the Linux writer spawn core: the plain
//! test twin (unchanged behavior, witness-wrapped error) and the
//! fault-injectable twin used to prove every `Unavailable` mapping records
//! its exact stage and raw OS errno. Never part of the production API.

use std::os::unix::net::UnixStream;

use runne_platform_ports::provider_credential_broker::VerifiedWriterLaunchSpec;

use super::provenance::{SpawnOperation, TestSpawnFailure};
use super::{
    SessionBusAddress, UnixRetainedWriterProcess, open_child_pidfd, spawn_with_secret_faulted,
};

pub(in crate::provider_credential_broker) fn spawn_with_pidfd_acquisition_for_tests(
    spec: &VerifiedWriterLaunchSpec,
    control_end: UnixStream,
    handshake_end: UnixStream,
    address: &SessionBusAddress,
) -> Result<UnixRetainedWriterProcess, TestSpawnFailure> {
    spawn_with_secret_faulted(
        spec,
        control_end,
        handshake_end,
        address,
        None,
        open_child_pidfd,
        &|_| None,
    )
    .map_err(TestSpawnFailure)
}

/// Fault-injectable test twin of the test spawn entry: `fault` receives each
/// operation stage in sequence and may return a synthetic errno to preempt
/// exactly that mapped operation. The returned witness keeps the unchanged
/// public error while exposing stage and errno.
pub(in crate::provider_credential_broker) fn spawn_with_injected_fault_for_tests(
    spec: &VerifiedWriterLaunchSpec,
    control_end: UnixStream,
    handshake_end: UnixStream,
    address: &SessionBusAddress,
    fault: impl Fn(SpawnOperation) -> Option<i32>,
) -> Result<UnixRetainedWriterProcess, TestSpawnFailure> {
    spawn_with_secret_faulted(
        spec,
        control_end,
        handshake_end,
        address,
        None,
        open_child_pidfd,
        &fault,
    )
    .map_err(TestSpawnFailure)
}
