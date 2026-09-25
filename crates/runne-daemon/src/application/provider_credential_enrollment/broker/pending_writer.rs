#[cfg(any(
    test,
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
use runne_api::ProviderCredentialBrokerTransferAuthority;
#[cfg(any(
    test,
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
use runne_platform_desktop::provider_credential_broker::ReceivedWriterProcessMeasurements;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
use runne_platform_desktop::provider_credential_broker::{
    MacOsPeerKillCapability, MacOsPeerKillPending,
};

#[cfg(any(
    test,
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
use super::{
    pending::{AwaitingVerifiedWriter, PendingBrokerRendezvousBinding},
    rendezvous::DaemonBrokerAuthority,
};

#[cfg(all(unix, feature = "desktop-protected"))]
#[path = "pending_writer/attestation_claims.rs"]
pub(super) mod attestation_claims;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[path = "pending_writer/native_writer.rs"]
mod native_writer;

#[cfg(target_os = "linux")]
#[path = "pending_writer/linux_writer.rs"]
mod linux_writer;

#[cfg(all(target_os = "linux", any(test, feature = "desktop-protected")))]
#[path = "pending_writer/linux_handshake.rs"]
mod linux_handshake;

#[cfg(all(target_os = "linux", any(test, feature = "desktop-protected")))]
#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "handshake core is test-driven until the D1 slice mounts it"
    )
)]
pub(crate) use linux_handshake::{receive_linux_writer_evidence, receive_linux_writer_handshake};
#[cfg(target_os = "linux")]
pub(crate) use linux_writer::{
    QualifiedWriterSessionMaterial, VerifiedLinuxWriterWithDaemonAuthority, WriterProcessFacts,
};

#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
#[path = "pending_writer/linux_orchestration.rs"]
mod linux_orchestration;

#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
#[path = "pending_writer/linux_admitted_launch.rs"]
mod linux_admitted_launch;

#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
#[cfg_attr(
    not(test),
    expect(
        unused_imports,
        reason = "launch orchestration is test-driven until the D1 slice mounts it"
    )
)]
pub(crate) use linux_orchestration::{
    LinuxWriterLaunchInputs, LinuxWriterSpawn, launch_linux_control_writer_with_handshake,
    launch_linux_pair_writer_with_handshake, launch_linux_writer_with_handshake,
};

#[cfg(all(target_os = "linux", feature = "desktop-protected"))]
pub(crate) use linux_admitted_launch::{
    launch_verified_linux_control_writer, launch_verified_linux_pair_writer,
};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[path = "pending_writer/qualified.rs"]
mod qualified;

/// Exact writer admitted to this rendezvous but not yet granted daemon kill authority.
#[cfg_attr(
    not(all(target_os = "macos", target_arch = "aarch64")),
    expect(
        dead_code,
        reason = "portable evidence tests retain native kill-admission members"
    )
)]
#[cfg(any(
    test,
    all(
        feature = "desktop-protected",
        target_os = "macos",
        target_arch = "aarch64"
    )
))]
pub(crate) struct VerifiedWriterAwaitingDaemonKillCapability {
    binding: PendingBrokerRendezvousBinding,
    authority: DaemonBrokerAuthority,
    transfer_authority: ProviderCredentialBrokerTransferAuthority,
    measurements: ReceivedWriterProcessMeasurements,
    handoff: runne_platform_desktop::provider_credential_broker::VerifiedDaemonWriterEndpointHandoffFacts,
}

/// Exact macOS writer captured by daemon but not kill-enabled before Desktop relinquishes.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct VerifiedMacOsWriterKillReady {
    binding: PendingBrokerRendezvousBinding,
    authority: DaemonBrokerAuthority,
    transfer_authority: ProviderCredentialBrokerTransferAuthority,
    kill: MacOsPeerKillPending,
    handoff: runne_platform_desktop::provider_credential_broker::VerifiedDaemonWriterEndpointHandoffFacts,
}

/// Exact macOS writer whose daemon-owned endpoint yielded a matching kernel token.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub(crate) struct VerifiedMacOsWriterWithDaemonKillCapability {
    binding: PendingBrokerRendezvousBinding,
    authority: DaemonBrokerAuthority,
    kill: MacOsPeerKillCapability,
    handoff: runne_platform_desktop::provider_credential_broker::VerifiedDaemonWriterEndpointHandoffFacts,
}

#[path = "pending_writer/evidence_flows.rs"]
mod evidence_flows;

#[cfg(test)]
#[path = "pending_writer_tests.rs"]
mod tests;
