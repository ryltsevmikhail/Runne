#[cfg(feature = "test-support")]
pub(super) fn record_present(
    connection: &rusqlite::Connection,
    taskrun_id: &[u8],
    attempt_id: &[u8],
) {
    use crate::store::test_support_diagnostics as diagnostics;

    const CHECKS: &[(&str, &str, bool)] = &[
        (
            "provider_admission",
            "SELECT EXISTS(SELECT 1 FROM provider_execution_admissions WHERE taskrun_id=?1 AND execution_attempt_id=?2)",
            false,
        ),
        (
            "provider_binding",
            "SELECT EXISTS(SELECT 1 FROM taskrun_provider_bindings WHERE taskrun_id=?1 AND attempt_id=?2)",
            false,
        ),
        (
            "dispatch_intent",
            "SELECT EXISTS(SELECT 1 FROM taskrun_dispatch_intents WHERE taskrun_id=?1 AND attempt_id=?2)",
            false,
        ),
        (
            "remote_request",
            "SELECT EXISTS(SELECT 1 FROM provider_remote_request_intents WHERE taskrun_id=?1 AND taskrun_attempt_id=?2)",
            false,
        ),
        (
            "response_binding",
            "SELECT EXISTS(SELECT 1 FROM provider_remote_response_bindings WHERE taskrun_id=?1 AND taskrun_attempt_id=?2)",
            false,
        ),
        (
            "remote_settlement",
            "SELECT EXISTS(SELECT 1 FROM provider_remote_terminal_settlements WHERE taskrun_id=?1 AND taskrun_attempt_id=?2)",
            false,
        ),
        (
            "artifact_cancel_closure",
            "SELECT EXISTS(SELECT 1 FROM provider_remote_artifact_cancel_closures WHERE taskrun_id=?1 AND taskrun_attempt_id=?2)",
            false,
        ),
        (
            "operation_proof",
            "SELECT EXISTS(SELECT 1 FROM provider_remote_operation_proofs WHERE taskrun_id=?1 AND taskrun_attempt_id=?2)",
            false,
        ),
        (
            "terminal_artifact",
            "SELECT EXISTS(SELECT 1 FROM provider_remote_terminal_artifacts WHERE taskrun_id=?1 AND taskrun_attempt_id=?2)",
            false,
        ),
        (
            "terminal_application",
            "SELECT EXISTS(SELECT 1 FROM provider_remote_terminal_applications WHERE taskrun_id=?1 AND taskrun_attempt_id=?2)",
            false,
        ),
        (
            "audit_receipt",
            "SELECT EXISTS(SELECT 1 FROM provider_remote_terminal_audit_receipts WHERE taskrun_id=?1 AND taskrun_attempt_id=?2)",
            false,
        ),
        (
            "cancel_fence",
            "SELECT EXISTS(SELECT 1 FROM taskrun_provider_cancel_fences WHERE taskrun_id=?1 AND taskrun_attempt_id=?2)",
            false,
        ),
        (
            "local_command_attempt",
            "SELECT EXISTS(SELECT 1 FROM taskrun_local_command_attempts WHERE taskrun_id=?1 AND (attempt_id IS NULL OR attempt_id=?2))",
            false,
        ),
        (
            "local_stop_receipt",
            "SELECT EXISTS(SELECT 1 FROM taskrun_local_command_stop_receipts WHERE taskrun_id=?1 AND attempt_id=?2)",
            false,
        ),
        (
            "terminal_settlement_receipt",
            "SELECT EXISTS(SELECT 1 FROM taskrun_terminal_settlement_receipts WHERE taskrun_id=?1)",
            true,
        ),
    ];
    for (category, sql, taskrun_only) in CHECKS {
        let result = if *taskrun_only {
            connection.query_row(sql, [taskrun_id], |row| row.get::<_, bool>(0))
        } else {
            connection.query_row(sql, [taskrun_id, attempt_id], |row| row.get::<_, bool>(0))
        };
        match result {
            Ok(true) => {
                diagnostics::record(match *category {
                    "provider_admission" => "cancel.no_admission.row.provider_admission",
                    "provider_binding" => "cancel.no_admission.row.provider_binding",
                    "dispatch_intent" => "cancel.no_admission.row.dispatch_intent",
                    "remote_request" => "cancel.no_admission.row.remote_request",
                    "response_binding" => "cancel.no_admission.row.response_binding",
                    "remote_settlement" => "cancel.no_admission.row.remote_settlement",
                    "artifact_cancel_closure" => "cancel.no_admission.row.artifact_cancel_closure",
                    "operation_proof" => "cancel.no_admission.row.operation_proof",
                    "terminal_artifact" => "cancel.no_admission.row.terminal_artifact",
                    "terminal_application" => "cancel.no_admission.row.terminal_application",
                    "audit_receipt" => "cancel.no_admission.row.audit_receipt",
                    "cancel_fence" => "cancel.no_admission.row.cancel_fence",
                    "local_command_attempt" => "cancel.no_admission.row.local_command_attempt",
                    "local_stop_receipt" => "cancel.no_admission.row.local_stop_receipt",
                    _ => "cancel.no_admission.row.terminal_settlement_receipt",
                });
                return;
            }
            Ok(false) => {}
            Err(_) => {
                diagnostics::record("cancel.no_admission.effect_rows_diagnostic_query");
                return;
            }
        }
    }
    diagnostics::record("cancel.no_admission.effect_rows_category_missing");
}

#[cfg(not(feature = "test-support"))]
pub(super) fn record_present(
    _connection: &rusqlite::Connection,
    _taskrun_id: &[u8],
    _attempt_id: &[u8],
) {
}
