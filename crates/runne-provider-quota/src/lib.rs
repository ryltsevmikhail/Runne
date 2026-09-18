#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(
    clippy::doc_markdown,
    clippy::match_same_arms,
    clippy::missing_const_for_fn,
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::redundant_pub_crate,
    clippy::significant_drop_tightening,
    clippy::use_self
)]

//! Bounded non-secret subscription quota evidence and state transitions.

mod model;
mod parser;
mod provider_parsers;
mod request;
mod serde_impl;
mod sink;
mod state;

pub use model::*;
pub use parser::*;
pub use provider_parsers::*;
pub use request::*;
pub use sink::*;
pub use state::*;

/// Durable subscription budget state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemainingState {
    /// No local budget has been seeded for this credential version.
    Missing,
    /// The durable budget is exhausted.
    Exhausted,
    /// Positive tokens remain.
    Remaining(u64),
}

/// Authority for the per-credential durable subscription budget.
pub trait SubscriptionBudgetAuthority: Send + Sync {
    /// Lazily seeds and returns the conservative local budget.
    fn seed_and_remaining(
        &self,
        provider_id: &str,
        credential_version: u64,
    ) -> Result<RemainingState, String>;
    /// Atomically spends tokens, flooring at zero.
    fn spend(
        &self,
        provider_id: &str,
        credential_version: u64,
        tokens: u64,
    ) -> Result<RemainingState, String>;
    /// Applies an absolute provider observation when the row is already known.
    fn refill_if_known(
        &self,
        provider_id: &str,
        credential_version: u64,
        remaining_tokens: u64,
        observed_at_high_water: i64,
    );
}
