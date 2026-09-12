//! Durable replay persistence for already-verified native qualification facts.
//!
//! This crate records one-time-use identities after qualification verification.
//! It does not authenticate evidence or grant bootstrap authority.

mod ledger;
mod model;
#[cfg(unix)]
mod path_guard;
mod record;
mod schema;

pub use ledger::{QualificationReplayLedger, QualificationReplayLedgerError};
pub use model::CanonicalRunBinding;
