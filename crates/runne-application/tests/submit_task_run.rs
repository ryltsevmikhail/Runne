//! X2 Step 2: atomic client-authorized TaskRun submit conformance (application layer).
//!
//! Submit must commit `TaskRunCreated + TaskRunQueued` as one unit-of-work with
//! one receipt, return `TaskRunSubmitted`, and reconcile lost acknowledgements
//! through the durable idempotency identity.

include!("submit_task_run_split_parts/store.rs");
include!("submit_task_run_split_parts/tests.rs");
