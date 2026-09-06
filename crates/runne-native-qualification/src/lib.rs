//! Fail-closed native qualification contracts.

#![forbid(unsafe_code)]

mod compiled_policy;
mod model;
mod relay;
mod verification;
mod wire;

pub use model::{
    PendingQualificationFault, QualificationFaultContext, QualificationFaultError,
    QualificationFaultSelector, QualificationProcessRole, VerifiedQualificationFault,
};
pub use relay::{QualificationFaultRelayCodecV1, QualificationFaultRelayError};
pub use verification::QualificationFaultVerifier;

/// Maximum accepted canonical fault-ticket wire size.
pub const MAX_FAULT_TICKET_BYTES: usize = 4_096;

#[cfg(test)]
mod tests;
