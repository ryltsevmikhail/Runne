#![deny(unsafe_code)]
#![deny(missing_docs)]

//! Target platform adapter crate for Phase 3 production gates.

pub mod certification;
pub mod containment;
pub mod fence;
/// Shared structured-command digests used by every local command adapter.
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod local_command_digest;
/// Structured, fail-closed local Linux command gate.
#[cfg(target_os = "linux")]
pub mod local_command_linux;
/// Structured, fail-closed local macOS command primitives.
#[cfg(target_os = "macos")]
pub mod local_command_macos;
/// Fail-closed native process contract stubs.
pub mod process_contract;
/// Linux cgroup-v2 process-area lifecycle primitive.
#[cfg(target_os = "linux")]
pub mod process_managed_area;

pub use containment::{
    AttestationVerdict, ContainmentBackendId, ContainmentBackendVersion, ContainmentError,
    ContainmentGate, ContainmentRequest, HostPlatform, NativeCertificate, RunnerIdentity,
    RuntimeProbe, StartupAttestor,
};
pub use process_contract::{
    LinuxProcessPlatformPort, MacOsProcessPlatformPort, NATIVE_SANDBOX_STATUS,
    PROCESS_CONTRACT_STATUS, WindowsProcessPlatformPort,
};
