use std::path::Path;

pub(crate) fn local_preapproval_diagnostic(runtime_root: &Path) -> String {
    let Ok(stage) =
        std::fs::read_to_string(runtime_root.join(".runne-test-protected-local-preapproval-stage"))
    else {
        return "unavailable".to_owned();
    };
    let stages: Vec<&str> = stage
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    if stages.is_empty() {
        return "unavailable".to_owned();
    }
    // Test-support daemon keeps an accumulated stage trace (one stage per
    // line); older daemons wrote exactly one stage name. Both shapes stay
    // readable, unknown stages stay visible instead of being masked.
    if stages.len() == 1 && is_preapproval_stage(stages[0]) {
        return stages[0].to_owned();
    }
    if stages.iter().all(|stage| is_preapproval_stage(stage)) {
        return stages.join(">");
    }
    "unrecognized".to_owned()
}

fn is_preapproval_stage(stage: &str) -> bool {
    [
        "admission",
        "open_held_files",
        "sealed_snapshot",
        "preflight",
        "digest",
        "managed_area_support",
        "current_managed_identity_mismatch",
        "current_legacy_identity_rejected",
        "ready",
        "current_approval_wait",
        "current_effective_mode_rejected",
        "current_invocation_scope_rejected",
        "current_managed_disposition_missing",
        "current_policy_denied",
        "current_admission_store_failed",
        "current_approval_request_invalid",
        "current_approval_review_rejected",
        "current_approval_summary_invalid",
        "current_approval_state_rejected",
        "current_approval_expired",
        "current_approval_task_not_running",
        "current_approval_rejected",
        "current_release_before",
        "current_release_failed",
        "current_release_done",
        "current_rejection_stale",
        "current_approval_other_error",
    ]
    .contains(&stage)
}

pub(crate) fn startup_diagnostic(runtime_root: &Path) -> String {
    let Ok(marker) =
        std::fs::read_to_string(runtime_root.join(".runne-test-protected-startup-stage"))
    else {
        return "unavailable".to_owned();
    };
    let simple = match marker.as_str() {
        "current_executable:unavailable" => Some("current_executable/unavailable"),
        "launch_accept:rejected" => Some("launch_accept/rejected"),
        "runtime_create:unavailable" => Some("runtime_create/unavailable"),
        "runtime_root:unavailable" => Some("runtime_root/unavailable"),
        "provider_dependencies:unavailable" => Some("provider_dependencies/unavailable"),
        "enrollment_revalidation:rejected" => Some("enrollment_revalidation/rejected"),
        "runtime_bootstrap:rejected" => Some("runtime_bootstrap/rejected"),
        "application_start:config" => Some("application_start/config"),
        "application_start:io" => Some("application_start/io"),
        "application_start:lock" => Some("application_start/lock"),
        "application_start:bootstrap" => Some("application_start/bootstrap"),
        "application_start:local_recovery" => Some("application_start/local_recovery"),
        "application_start:taskrun_assignment_recovery" => {
            Some("application_start/taskrun_assignment_recovery")
        }
        "application_start:pre_effect_recovery" => Some("application_start/pre_effect_recovery"),
        "application_start:schema" => Some("application_start/schema"),
        "application_start:store_identity" => Some("application_start/store_identity"),
        "application_start:store_admission" => Some("application_start/store_admission"),
        "application_start:store_unavailable" => Some("application_start/store_unavailable"),
        "session_service:unavailable" => Some("session_service/unavailable"),
        "session_clock:unavailable" => Some("session_clock/unavailable"),
        "root_control:unavailable" => Some("root_control/unavailable"),
        "ready_v1:rejected" => Some("ready_v1/rejected"),
        "ready_v2:rejected" => Some("ready_v2/rejected"),
        _ => None,
    };
    if let Some(simple) = simple {
        return simple.to_owned();
    }
    let Some(stage) = marker.strip_prefix("application_start:local_recovery_") else {
        return store_diagnostic(&marker);
    };
    if [
        "scan",
        "renew_node_lease",
        "authorize",
        "load_stream",
        "replay_stream",
        "mark_unconfirmed",
        "prove_empty",
        "settle_unknown",
        "remove_area",
        "request_stop",
        "check_area",
        "confirm_stop",
        "complete_route_lookup",
        "complete_current",
        "complete_legacy",
        "complete_stop_conflict",
        "missing_exit_code",
        "complete_taskrun",
        "missing_terminal_event",
        "settle_terminal",
        "area_populated_at_terminal",
        "unexpected_terminal_state",
    ]
    .contains(&stage)
    {
        return format!("application_start/local_recovery_{stage}");
    }
    "unrecognized".to_owned()
}

fn store_diagnostic(marker: &str) -> String {
    let Some(store) = marker.strip_prefix("application_start:store_") else {
        return "unrecognized".to_owned();
    };
    let mut parts = store.split('_');
    let (Some(purpose), Some(stage), Some(reason), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return "unrecognized".to_owned();
    };
    if !["replay", "writer", "reader", "reservation", "other"].contains(&purpose)
        || !["open", "verify"].contains(&stage)
        || !["identity", "admission", "unavailable"].contains(&reason)
    {
        return "unrecognized".to_owned();
    }
    format!("application_start/store_{purpose}_{stage}_{reason}")
}

pub(crate) fn start(
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    root: &Path,
) {
    let result = if crate::t1_credential_companion::enabled() {
        supervisor.start_capturing_for_test(crate::random_secret())
    } else {
        supervisor.start()
    };
    if let Err(error) = result {
        panic!(
            "protected T1 launch failed; startup_stage={}; error={error}",
            startup_diagnostic(root),
        );
    }
}
