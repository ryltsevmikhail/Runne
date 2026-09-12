//! Fail-closed native qualification contracts.

#![forbid(unsafe_code)]

mod admission;
mod admission_relay;
mod admission_relay_codec;
mod admission_verification;
mod bootstrap_model;
mod bootstrap_pending;
mod bootstrap_policy;
mod bootstrap_verification;
mod bootstrap_wire;
mod compiled_policy;
mod context_model;
mod context_policy;
mod context_relay;
mod context_verification;
mod context_wire;
mod fence_facts;
mod model;
mod pending;
mod pending_context;
mod relay;
mod verification;
mod wire;

pub use admission::{PendingQualificationAdmission, QualificationAdmissionError};
pub use admission_relay::{
    QualificationAdmissionRelayError, QualificationAdmissionRelayTranscript,
};
pub use admission_relay_codec::QualificationAdmissionRelayCodecV1;
pub use admission_verification::{
    QualificationAdmissionVerificationError, QualificationAdmissionVerifier,
};
pub use bootstrap_model::{
    QualificationRunBootstrapError, QualificationRunBootstrapExpectation,
    VerifiedQualificationRunBootstrapProof,
};
pub use bootstrap_pending::PendingQualificationRunBootstrapProof;
pub use bootstrap_verification::QualificationRunBootstrapVerifier;
pub use context_model::{
    QualificationRunContextError, QualificationRunContextExpectation, QualificationScenario,
    VerifiedQualificationRunContext,
};
pub use context_relay::{QualificationRunContextRelayCodecV1, QualificationRunContextRelayError};
pub use context_verification::QualificationRunContextVerifier;
pub use fence_facts::VerifiedQualificationFenceFacts;
pub use model::{
    QualificationFaultContext, QualificationFaultError, QualificationFaultSelector,
    QualificationProcessRole, VerifiedQualificationFault,
};
pub use pending::PendingQualificationFault;
pub use pending_context::PendingQualificationRunContext;
pub use relay::{QualificationFaultRelayCodecV1, QualificationFaultRelayError};
pub use verification::QualificationFaultVerifier;

/// Maximum accepted canonical fault-ticket wire size.
pub const MAX_FAULT_TICKET_BYTES: usize = 4_096;

/// Maximum accepted canonical signed bootstrap-proof wire size.
pub const MAX_RUN_BOOTSTRAP_PROOF_BYTES: usize = 2_048;

/// Maximum accepted canonical runner-context wire size.
pub const MAX_RUN_CONTEXT_BYTES: usize = 2_048;

/// Maximum accepted version-1 admission bundle size.
pub const MAX_ADMISSION_BUNDLE_BYTES: usize = 8_192;

#[cfg(test)]
mod tests;
