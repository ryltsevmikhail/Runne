#![cfg(target_os = "linux")]

//! X2 kill-based fault round (phase-3 residue item 5): SIGKILL the real
//! daemon process at a deterministic durable-boundary point while a client
//! submit is in flight, relaunch, and prove commit-before-ACK reconciliation
//! on the durable store — no simulation, no random delay.
//!
//! Scenario (deterministic handshake, see `commit_gate` in `runne-store`):
//! 1. Launch the real `runned` binary through the protected bundled-runtime
//!    harness (first activation completed), arm the commit gate, and connect
//!    one authenticated client.
//! 2. Seed a project, workspace, and conversation through the daemon's HTTP surface.
//! 3. Fire an atomic TaskRun submit with a fixed command identity and wait
//!    for the commit-gate marker — proof that the daemon already executed
//!    the durable SQLite `tx.commit()` for the `Created + Queued` batch.
//! 4. Assert the acknowledgement has NOT been delivered to the client while
//!    the marker exists, then SIGKILL the exact owned daemon child PID.
//! 5. Reap the child, relaunch the daemon on the same durable store,
//!    reconnect, and replay the identical submit (same request identity).
//! 6. Assert exactly-once convergence: the store holds exactly one
//!    `Created + Queued` TaskRun, the retry replays one `submitted`
//!    acknowledgement at stream version 2 (stored receipt, no new events),
//!    and the killed attempt never received its ACK before the kill.

use runne_platform_desktop::{
    BundledRuntimeProcessStatus, DevelopmentBundledRuntimeLauncher,
    ProtectedBundledRuntimeLaunchSpec,
};
use runne_runtime_client::{CanonicalId, CommandIdentity, SubmitTaskRunRequest};

use std::sync::LazyLock;

use std::time::{Duration, Instant};

#[path = "support/owner_private.rs"]
mod owner_private;

static KILL_FAULT_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// Generate canonical v7 IDs once per process; the submit command identity is
// reused unchanged across the killed attempt and retry.
static CONVERSATION_ID: LazyLock<CanonicalId> = LazyLock::new(CanonicalId::now_v7);
static WORKSPACE_ID: LazyLock<CanonicalId> = LazyLock::new(CanonicalId::now_v7);
static PROJECT_ID: LazyLock<CanonicalId> = LazyLock::new(CanonicalId::now_v7);
static SUBMIT_COMMAND_ID: LazyLock<CanonicalId> = LazyLock::new(CanonicalId::now_v7);

include!("kill_fault_parts/kill_submit.rs");
