//! Fixture support for `session list` / `resume` CLI tests: sessions are
//! seeded through the public runtime client (atomic `TaskRun` submit), the CLI
//! observes them only through its own commands.

#![cfg(unix)]

#[allow(dead_code)]
#[path = "../task_cli_parts/support.rs"]
pub mod task_support;

pub use task_support::{
    exit_code, parse_json_error_envelope, run_cli, start_test_daemon, stop_daemon,
};

use std::path::Path;

use runne_runtime_client::{AuthenticatedRuntimeClient, CanonicalId};

/// Connects a public client and submits one `TaskRun` in a fresh
/// conversation/workspace; returns (`conversation_id`, `workspace_id`).
async fn seed_exec_session(
    profile: &Path,
) -> (CanonicalId, CanonicalId, AuthenticatedRuntimeClient) {
    let client = task_support::connect_client(profile).await;
    let (conversation_id, workspace_id) = task_support::seed_conversation(&client).await;
    task_support::submit_run(&client, conversation_id, workspace_id).await;
    (conversation_id, workspace_id, client)
}

/// Seeds one session; returns (`conversation_id`, `workspace_id`).
pub async fn seed_one_exec_session(profile: &Path) -> (CanonicalId, CanonicalId) {
    let (conversation_id, workspace_id, _client) = seed_exec_session(profile).await;
    (conversation_id, workspace_id)
}

/// Seeds two sessions in submission order.
pub async fn seed_two_exec_sessions(profile: &Path) -> (CanonicalId, CanonicalId, CanonicalId) {
    let (first, workspace_id, _client) = seed_exec_session(profile).await;
    let (second, _workspace_id, _client) = seed_exec_session(profile).await;
    (first, second, workspace_id)
}

/// The authoritative number of committed `TaskRun`s observed by the runtime.
pub async fn task_run_count(profile: &Path) -> usize {
    let client = task_support::connect_client(profile).await;
    client.list_task_runs().await.expect("list task runs").len()
}
