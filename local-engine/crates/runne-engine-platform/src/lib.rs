//! runne-engine-platform: runtime-neutral process ownership primitives for the
//! Local Engine — limits, opaque process trees, launch/validation and
//! bounded dual-owner cleanup contracts. No business logic, no network.

pub mod local_process;
pub mod supervisor;

pub use local_process::{
    HostGeneration, LocalProcessLimitEnvelope, LocalProcessSpec, ProcessEvidence, WorkerGeneration,
};
pub use supervisor::{LocalHostSupervisor, SupervisorConfig, SupervisorError, wait_for};
