#![deny(unsafe_code)]
#![deny(missing_docs)]

//! Target platform adapter crate for Phase 3 production gates.

pub mod certification;
pub mod containment;
pub mod fence;
/// Fail-closed native process contract stubs.
pub mod process_contract;

pub use containment::{
    AttestationVerdict, ContainmentBackendId, ContainmentBackendVersion, ContainmentError,
    ContainmentGate, ContainmentRequest, HostPlatform, NativeCertificate, RunnerIdentity,
    RuntimeProbe, StartupAttestor,
};
pub use process_contract::{
    LinuxProcessPlatformPort, MacOsProcessPlatformPort, NATIVE_SANDBOX_STATUS,
    PROCESS_CONTRACT_STATUS, WindowsProcessPlatformPort,
};
