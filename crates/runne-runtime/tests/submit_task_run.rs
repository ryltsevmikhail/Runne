//! X2 Step 4: atomic submit wired through the runtime host (SQLite slice).
//!
//! Submit must reach the application unit-of-work through the runtime
//! ingress/supervisor as one `Created + Queued` batch, replay the stored
//! receipt on lost acknowledgements, conflict on a changed payload under the
//! same identity, and leave the aggregate cancellable on the canonical host.

#[path = "../../runne-store/tests/support/validated_reopen.rs"]
mod validated_reopen;

include!("submit_task_run_split_parts/harness.rs");
include!("submit_task_run_split_parts/tests.rs");
