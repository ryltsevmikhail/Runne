//! Application ports — abstract traits for persistence, identity, and time.
//!
//! All ports are trait-only; no concrete adapters in this crate.

use runne_domain::agent_loop::{StepOutcomeRef, WakeCondition, WakeEvidenceRef};
use runne_domain::conversation::ConversationEvent;
use runne_domain::event::{EventEnvelope, UncommittedEvent};
use runne_domain::id::{
    AttemptId, CheckpointId, CommandId, ConversationId, CycleId, EventId, IdempotencyKey,
    IntegrityDigest, MessageId, PlanEvaluationId, TaskRunId, WorkspaceId,
};
use runne_domain::recovery::ReconciliationResultRef;
use runne_domain::reference::BudgetReservationRef;
use runne_domain::task_run::TaskRunEvent;
use runne_domain::timestamp::Timestamp;
use runne_domain::verification::PlanEvaluationRef;

use crate::commands::CommandOutcome;
use crate::fingerprint::CommandFingerprint;

include!("ports/event_store_task_run.rs");
include!("ports/taskrun_claim.rs");
include!("ports/taskrun_release.rs");
include!("ports/taskrun_assignment.rs");
include!("ports/event_store.rs");
include!("ports/unit_of_work.rs");
include!("ports/runtime.rs");
include!("ports/idempotency.rs");
include!("ports/project_workspace.rs");
include!("ports/workspace_files.rs");
include!("ports/workspace_editor.rs");
include!("ports/workspace_diff.rs");
include!("ports/process.rs");
include!("ports/reexports.rs");

#[cfg(test)]
mod tests {
    include!("ports/tests.rs");
}
