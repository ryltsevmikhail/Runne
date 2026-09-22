//! X2 kill-based fault round (phase-3 residue item 5): SIGKILL the real
//! daemon process while a client submit is in flight, relaunch, and prove
//! commit-before-ACK reconciliation on the durable store — no simulation.
//!
//! Scenario:
//! 1. Launch the real `runned` binary through the protected bundled-runtime
//!    harness (first activation completed) and connect one authenticated
//!    client.
//! 2. Seed a project/workspace through the daemon's HTTP surface.
//! 3. Fire an atomic TaskRun submit with a fixed command identity and kill
//!    the daemon with SIGKILL at a random point while the request is in
//!    flight (before, during, or after the durable commit; the reply may or
//!    may not reach the client).
//! 4. Relaunch the daemon, reconnect, and replay the identical submit.
//! 5. Assert exactly-once convergence: the store holds exactly one
//!    `Created + Queued` batch for one taskrun ID, the retry returns one
//!    `submitted` acknowledgement at stream version 2, and the previous
//!    client's observed acknowledgement (if any) matches the replayed one.

use rand::{RngCore as _, rngs::OsRng};
use runne_platform_desktop::{
    BundledRuntimeProcessStatus, DevelopmentBundledRuntimeLauncher,
    ProtectedBundledRuntimeLaunchSpec,
};
use runne_runtime_client::{CanonicalId, CommandIdentity, SubmitTaskRunRequest};

use std::sync::LazyLock;

use std::time::Duration;

#[path = "support/owner_private.rs"]
mod owner_private;

static KILL_FAULT_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// Fixed UUIDs fail server-side validation (invalid_command_id / invalid_project_id);
// generate fresh v7 IDs once per process and share them across attempt/retry sites.
static CONVERSATION_ID: LazyLock<CanonicalId> = LazyLock::new(CanonicalId::now_v7);
static WORKSPACE_ID: LazyLock<CanonicalId> = LazyLock::new(CanonicalId::now_v7);
static PROJECT_ID: LazyLock<CanonicalId> = LazyLock::new(CanonicalId::now_v7);
static SUBMIT_COMMAND_ID: LazyLock<CanonicalId> = LazyLock::new(CanonicalId::now_v7);

include!("kill_fault_parts/kill_submit.rs");
