#![deny(unsafe_code)]
#![deny(missing_docs)]

//! Target platform adapter crate for Phase 3 production gates.

pub mod certification;
pub mod containment;
pub mod fence;
/// Structured, fail-closed local Linux command gate.
#[cfg(target_os = "linux")]
pub mod local_command_linux;
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
