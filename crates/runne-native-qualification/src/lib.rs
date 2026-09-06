//! Fail-closed native qualification contracts.

#![forbid(unsafe_code)]

mod admission;
mod compiled_policy;
mod context_model;
mod context_policy;
mod context_verification;
mod context_wire;
mod model;
mod pending;
mod relay;
mod verification;
mod wire;

pub use admission::{PendingQualificationAdmission, QualificationAdmissionError};
pub use context_model::{
    QualificationRunContextError, QualificationRunContextExpectation, QualificationScenario,
    VerifiedQualificationRunContext,
};
pub use context_verification::QualificationRunContextVerifier;
pub use model::{
    QualificationFaultContext, QualificationFaultError, QualificationFaultSelector,
    QualificationProcessRole, VerifiedQualificationFault,
};
pub use pending::PendingQualificationFault;
pub use relay::{QualificationFaultRelayCodecV1, QualificationFaultRelayError};
pub use verification::QualificationFaultVerifier;

/// Maximum accepted canonical fault-ticket wire size.
pub const MAX_FAULT_TICKET_BYTES: usize = 4_096;

/// Maximum accepted canonical runner-context wire size.
pub const MAX_RUN_CONTEXT_BYTES: usize = 2_048;

/// Maximum accepted version-1 admission bundle size.
pub const MAX_ADMISSION_BUNDLE_BYTES: usize = 8_192;

#[cfg(test)]
mod tests;
