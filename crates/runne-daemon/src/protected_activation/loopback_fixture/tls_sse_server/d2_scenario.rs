pub(super) fn selected(runtime_root: &std::path::Path) -> Result<Option<String>, ()> {
    let Ok(scenario) = std::env::var("RUNNE_TEST_D2_TOOL_SCENARIO") else {
        return Ok(None);
    };
    if !matches!(
        scenario.as_str(),
        "read-create-stop"
            | "finish-before-cancel"
            | "result-commit-crash"
            | "crash-before-go"
            | "crash-pending-approval"
            | "crash-approved-before-lease"
            | "crash-claimed-before-area"
            | "crash-after-create-effect"
            | "stale-after-read"
            | "outside-target"
            | "excluded-target"
            | "cancel-final-response"
            | "stale-final-target"
            | "budget-exhausted"
            | "deny-create"
            | "deny-read"
            | "stale-approval"
            | "approval-expiry"
            | "revoke-before-lease"
            | "incomplete-provider-response"
            | "unknown-tool-proposal"
            | "malformed-tool-arguments"
            | "early-final-stop"
            | "approved-target-create-race"
            | "target-changed-before-go"
            | "cancel-before-go"
            | "cancel-after-create-effect"
            | "cancel-restart-after-create-effect"
            | "stale-after-result"
            | "truncated-read-result"
            | "restart-started-before-cycle"
            | "restart-cycle-before-budget"
            | "restart-context-committed"
            | "restart-cancelled-before-budget"
            | "restart-plan-committed"
            | "restart-proposal-before-invocation"
            | "restart-dispatched-remote-unknown"
    ) {
        return Err(());
    }
    std::fs::write(
        runtime_root.join(".runne-test-d2-scenario-selected"),
        scenario.as_bytes(),
    )
    .map_err(|_| ())?;
    Ok(Some(scenario))
}
