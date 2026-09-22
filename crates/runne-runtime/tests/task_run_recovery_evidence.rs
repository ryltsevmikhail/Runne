//! X2 phase 3: fault/observer/reconnect evidence + recovery invariants.
//!
//! Real fault scenarios on the machine (native Linux, dev-fleet policy):
//! genuine runtime restarts with validated store reopen, genuine reply/channel
//! races and concurrent writers. Simulated layers (if any) are marked in the
//! test name or doc comment.
//!
//! Invariants (plan 18 §D1.3/X2, report 2026-09-17-x2.md «Незавершённые слои»):
//! 1. Lost-ACK reconciliation survives a runtime restart (cross-restart
//!    duplicate submit replays the stored receipt; no new events).
//! 2. Uncertain outcome under immediate-shutdown fault remains reconcilable:
//!    exactly-once effect on retry, never a Created-only orphan.
//! 3. Rejected-after-fence submit leaves no state; retry commits cleanly.
//! 4. Observers never observe a Created-only intermediate state and cannot
//!    mutate (read-only host surface).
//! 5. Concurrent duplicate submits (same identity) commit exactly one batch.

#[path = "../../runne-store/tests/support/validated_reopen.rs"]
mod validated_reopen;

include!("task_run_recovery_parts/harness.rs");
include!("task_run_recovery_parts/tests.rs");
