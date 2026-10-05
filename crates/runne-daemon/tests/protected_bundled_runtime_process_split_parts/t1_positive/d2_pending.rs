use super::*;

#[path = "d2_pending/diagnostic.rs"]
mod diagnostic;
#[path = "d2_pending/d2_faults.rs"]
mod faults;
#[path = "d2_pending/fixture.rs"]
mod fixture;
#[path = "d2_positive.rs"]
mod positive;

#[expect(
    clippy::too_many_arguments,
    reason = "Fixture plumbing keeps the exact native process, authority, barrier, and filesystem handles together."
)]
pub(super) async fn dispatch_if_requested(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    conversation_id: runne_runtime_client::CanonicalId,
    workspace_id: runne_runtime_client::CanonicalId,
    temporary_root: &std::path::Path,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    executable: &std::path::Path,
    session_bus_socket: &std::path::Path,
) -> bool {
    if std::env::var_os("RUNNE_TEST_D2_TOOL_PROPOSAL").is_none() {
        return false;
    }
    let admitted_directory = temporary_root.join("rebound-project");
    exercise(
        client,
        conversation_id,
        workspace_id,
        &admitted_directory,
        database,
        runtime_root,
        supervisor,
        executable,
        session_bus_socket,
    )
    .await;
    true
}

#[expect(
    clippy::too_many_arguments,
    reason = "Fixture plumbing keeps the exact native process, authority, barrier, and filesystem handles together."
)]
pub(super) async fn exercise(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    conversation_id: runne_runtime_client::CanonicalId,
    workspace_id: runne_runtime_client::CanonicalId,
    project_directory: &std::path::Path,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    executable: &std::path::Path,
    session_bus_socket: &std::path::Path,
) {
    match std::env::var("RUNNE_TEST_D2_TOOL_SCENARIO").as_deref() {
        Ok(
            "read-create-stop"
            | "finish-before-cancel"
            | "cancel-final-response"
            | "stale-final-target"
            | "budget-exhausted"
            | "deny-create"
            | "result-commit-crash"
            | "crash-before-go"
            | "crash-approved-before-lease"
            | "crash-claimed-before-area"
            | "crash-after-create-effect"
            | "stale-after-result",
        ) => {
            positive::exercise(
                client,
                conversation_id,
                workspace_id,
                project_directory,
                database,
                runtime_root,
                supervisor,
                executable,
                session_bus_socket,
            )
            .await;
        }
        Ok(
            scenario @ ("deny-read"
            | "stale-approval"
            | "approval-expiry"
            | "revoke-before-lease"
            | "incomplete-provider-response"
            | "target-changed-before-go"
            | "outside-target"
            | "excluded-target"
            | "cancel-before-go"
            | "cancel-after-create-effect"
            | "cancel-restart-after-create-effect"
            | "truncated-read-result"
            | "unknown-tool-proposal"
            | "malformed-tool-arguments"
            | "early-final-stop"
            | "stale-after-read"),
        ) => {
            faults::exercise(
                scenario,
                client,
                conversation_id,
                workspace_id,
                project_directory,
                database,
                runtime_root,
                supervisor,
                executable,
                session_bus_socket,
            )
            .await;
        }
        _ => {
            fixture::exercise(
                client,
                conversation_id,
                workspace_id,
                project_directory,
                database,
                runtime_root,
                supervisor,
                executable,
                session_bus_socket,
            )
            .await;
        }
    }
}
