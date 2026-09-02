#![forbid(unsafe_code)]

mod admission;
mod backend;
mod session;

#[cfg(test)]
mod tests;

pub use backend::{
    CredentialBackendResult, CredentialMutationEffect, CredentialRuntimeReadEffect,
    CredentialRuntimeReadObservation,
};
pub use session::{
    CredentialRegistrationOutcome, CredentialServiceActivity, CredentialServiceCore,
    CredentialServiceIngressFailure,
};
