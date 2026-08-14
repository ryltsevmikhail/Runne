//! Closed authoritative-command reconciliation contracts.

mod context;
mod disposition;
mod host;
mod outcome;
mod witness;

pub use context::{CommandReconciliationContext, ReconciliationOperation};
pub use disposition::CommandReconciliationDisposition;
pub use host::{CommandReconciliationHostError, CommandReconciliationHostPort};
pub use outcome::{
    AuthoritativeCommandOutcome, AuthoritativeCommandOutcomeRef,
    AuthoritativeTextGenerationOutcome, AuthoritativeTextGenerationOutcomeRef,
};
pub use witness::{CommandReconciliationWitness, CommandReconciliationWitnessRef};
