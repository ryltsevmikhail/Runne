//! Application ports — abstract traits for persistence, identity, and time.
//!
//! All ports are trait-only; no concrete adapters in this crate.

use gocode_domain::agent_loop::{StepOutcomeRef, WakeCondition, WakeEvidenceRef};
use gocode_domain::conversation::ConversationEvent;
use gocode_domain::event::{EventEnvelope, UncommittedEvent};
use gocode_domain::id::{
    AttemptId, CheckpointId, CommandId, ConversationId, CycleId, EventId, IdempotencyKey,
    IntegrityDigest, MessageId, PlanEvaluationId, TaskRunId, WorkspaceId,
};
use gocode_domain::recovery::ReconciliationResultRef;
use gocode_domain::reference::BudgetReservationRef;
use gocode_domain::task_run::TaskRunEvent;
use gocode_domain::timestamp::Timestamp;
use gocode_domain::verification::PlanEvaluationRef;

use crate::commands::CommandOutcome;
use crate::fingerprint::CommandFingerprint;

include!("ports/event_store.rs");
include!("ports/unit_of_work.rs");
include!("ports/runtime.rs");
include!("ports/idempotency.rs");
include!("ports/reexports.rs");

#[cfg(test)]
mod tests {
    include!("ports/tests.rs");
}
