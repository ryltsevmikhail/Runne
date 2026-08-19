//! Fixture-only RC2 pre-sign claim fencing; production has no signing executor.
#![allow(clippy::redundant_pub_crate)] // Durable authority needs internal codec reexports.

#[path = "rc2_effect_lease_closure.rs"]
mod closure;
#[path = "rc2_effect_lease_durable.rs"]
mod durable;
#[path = "rc2_effect_lease_evidence.rs"]
mod evidence;
#[path = "rc2_effect_lease_ledger.rs"]
mod ledger;
#[path = "rc2_effect_lease_merge.rs"]
mod merge;
#[path = "rc2_effect_lease_reconciliation.rs"]
mod reconciliation;
#[path = "rc2_effect_lease_types.rs"]
mod types;

#[allow(unused_imports)]
// Private durable fixture utility remains available to internal modules.
pub(crate) use durable::DurableFixtureRc2EffectLeaseLedger;
pub(crate) use durable::{decode_ledger, encode_ledger};
pub(crate) use ledger::FixtureRc2EffectLeaseLedger;
pub(crate) use ledger::StoredRawEvidence;
pub(crate) use types::FixtureRc2EffectClosure;
#[allow(unused_imports)] // Internal modules consume selected fixture-only opaque types.
pub use types::{
    EffectLeaseError, FixtureRc2SigningAuthorization, FixtureRc2SigningDispatchLease,
    FixtureRc2SigningDispatchLeases, Rc2SigningAuthorizationFixture,
    Rc2SigningBackendReadbackFixture, Rc2SigningEffectClaim, Rc2SigningEffectLeaseState,
};
