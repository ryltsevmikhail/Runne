#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Target platform adapter crate for Phase 3 production gates.

pub mod certification;
pub mod containment;
pub mod fence;

pub use containment::{
    AttestationVerdict, ContainmentBackendId, ContainmentBackendVersion, ContainmentError,
    ContainmentGate, ContainmentRequest, HostPlatform, NativeCertificate, RunnerIdentity,
    RuntimeProbe, StartupAttestor,
};
