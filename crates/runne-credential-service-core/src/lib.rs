#![forbid(unsafe_code)]

mod admission;
mod backend;
pub(crate) mod session;

#[cfg(test)]
mod tests;

pub use backend::{
    CredentialBackendResult, CredentialMutationEffect, CredentialRuntimeReadEffect,
    CredentialRuntimeReadObservation,
};
pub use session::{
    CredentialRegistrationOutcome, CredentialServiceActivity, CredentialServiceCore,
    CredentialServiceIngressFailure, QualificationResourceBudget,
};
