//! Plan revision model — immutable planning output.
//!
//! PlanRevision binds exact cycle, context, observations, and policy
//! references into a committed planning output.

use crate::agent_loop::ProposalActionType;
use crate::context::ContextManifestRef;
use crate::id::{CycleId, IntegrityDigest, PlanId, TaskRunId};
use crate::reference::{BudgetReservationRef, ResultRef};
use crate::timestamp::Timestamp;

include!("plan/models.rs");

#[cfg(test)]
mod tests {
    include!("plan/tests.rs");
}
