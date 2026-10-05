#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
pub(super) fn application_error_code(
    error: &runne_application::errors::ApplicationError,
) -> &'static str {
    use runne_application::errors::ApplicationError as Error;
    match error {
        Error::Domain(_) => "domain",
        Error::VersionConflict { .. } => "version_conflict",
        Error::VersionExhausted { .. } => "version_exhausted",
        Error::IdempotencyConflict { .. } => "idempotency_conflict",
        Error::IdGenerationFailed(_) => "id_generation",
        Error::InvalidCommandFingerprint(_) => "fingerprint",
        Error::EventStoreFailed(_) => "event_store",
        Error::StorageFailed(kind) => match kind {
            runne_application::ports::StorageFailureKind::PolicyDenied => "storage_policy_denied",
            runne_application::ports::StorageFailureKind::CorruptData => "storage_corrupt",
            runne_application::ports::StorageFailureKind::UnsupportedSchema => "storage_schema",
            runne_application::ports::StorageFailureKind::IntegrityViolation => "storage_integrity",
            runne_application::ports::StorageFailureKind::WriterFenced => "storage_writer_fenced",
            runne_application::ports::StorageFailureKind::Unavailable => "storage_unavailable",
        },
        Error::AggregateNotFound { .. } => "aggregate_not_found",
        Error::StreamConsistencyViolation(_) => "stream_consistency",
        Error::CommitVersionMismatch { .. } => "commit_version_mismatch",
        Error::TimePortFailed(_) => "time_port",
        Error::RetryScheduleRejected(_) => "retry_schedule",
        Error::WakeEvidenceRejected(_) => "wake_evidence",
        Error::ReconciliationRejected(_) => "reconciliation",
        Error::VerificationRejected(_) => "verification",
        Error::InvalidAuthorityResult => "authority_result",
    }
}

#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
pub(super) fn application_error_stage(
    prefix: &'static str,
    error: &runne_application::errors::ApplicationError,
) -> &'static str {
    match (prefix, application_error_code(error)) {
        ("context", "domain") => "context_error_domain",
        ("context", "version_conflict") => "context_error_version",
        ("context", "storage_policy_denied") => "context_error_storage_policy_denied",
        ("context", "storage_corrupt") => "context_error_storage_corrupt",
        ("context", "storage_schema") => "context_error_storage_schema",
        ("context", "storage_integrity") => "context_error_storage_integrity",
        ("context", "storage_writer_fenced") => "context_error_storage_writer_fenced",
        ("context", "storage_unavailable") => "context_error_storage_unavailable",
        ("context", "event_store") => "context_error_event_store",
        ("context", "idempotency_conflict") => "context_error_idempotency",
        ("context", "fingerprint") => "context_error_fingerprint",
        ("context", _) => "context_error_other",
        ("plan", "domain") => "plan_error_domain",
        ("plan", "version_conflict") => "plan_error_version",
        ("plan", "storage_policy_denied") => "plan_error_storage_policy_denied",
        ("plan", "storage_corrupt") => "plan_error_storage_corrupt",
        ("plan", "storage_schema") => "plan_error_storage_schema",
        ("plan", "storage_integrity") => "plan_error_storage_integrity",
        ("plan", "storage_writer_fenced") => "plan_error_storage_writer_fenced",
        ("plan", "storage_unavailable") => "plan_error_storage_unavailable",
        ("plan", "event_store") => "plan_error_event_store",
        ("plan", "idempotency_conflict") => "plan_error_idempotency",
        ("plan", "fingerprint") => "plan_error_fingerprint",
        ("plan", _) => "plan_error_other",
        _ => "unknown",
    }
}

#[cfg(all(
    feature = "desktop-protected",
    target_os = "linux",
    feature = "test-support"
))]
pub(crate) fn d2_test_stage(stage: &'static str) {
    const ALLOWED: &[&str] = &[
        "start_cycle",
        "start_cycle_error",
        "cycle_started",
        "commit_context",
        "context_error_domain",
        "context_error_version",
        "context_error_storage_policy_denied",
        "context_error_storage_corrupt",
        "context_error_storage_schema",
        "context_error_storage_integrity",
        "context_error_storage_writer_fenced",
        "context_error_storage_unavailable",
        "context_error_event_store",
        "context_error_idempotency",
        "context_error_fingerprint",
        "context_error_other",
        "context_committed",
        "commit_plan",
        "plan_error_domain",
        "plan_error_version",
        "plan_error_storage_policy_denied",
        "plan_error_storage_corrupt",
        "plan_error_storage_schema",
        "plan_error_storage_integrity",
        "plan_error_storage_writer_fenced",
        "plan_error_storage_unavailable",
        "plan_error_event_store",
        "plan_error_idempotency",
        "plan_error_fingerprint",
        "plan_error_other",
        "plan_committed",
        "restart_budget_read",
        "restart_budget_attempt",
        "restart_invocations_read",
        "restart_result_missing",
        "restart_budget_missing_with_invocations",
        "restart_authority",
        "restart_safe_stop",
        "restart_cycle_failure",
        "restart_loop_service",
        "restart_origin_missing",
        "restart_conversation",
        "restart_message_missing",
        "restart_message_duplicate",
        "restart_message_invalid",
        "restart_started_receipt",
        "restart_started_mismatch",
        "restart_version",
        "restart_text",
        "restart_failure_projection",
        "restart_pre_cycle_projection",
        "restart_finish_receipt_mismatch",
        "restart_finish_commit",
        "restart_finish_conflict",
        "restart_finish_data_unavailable",
        "restart_finish_other",
        "cancel_d2_begin",
        "cancel_d2_stream_error",
        "cancel_d2_old_head",
        "cancel_d2_replay_error",
        "cancel_d2_not_cancelling",
        "cancel_d2_finish_error_conflict",
        "cancel_d2_finish_error_receipt",
        "cancel_d2_finish_error_storage",
        "cancel_d2_finish_error_storage_integrity",
        "cancel_d2_finish_error_storage_fenced",
        "cancel_d2_finish_error_storage_unavailable",
        "cancel_d2_finish_error_storage_other",
        "cancel_d2_finish_error_domain",
        "cancel_d2_finish_error_other",
        "cancel_d2_finished",
    ];
    if !ALLOWED.contains(&stage)
        || std::env::var_os("RUNNE_TEST_D2_TOOL_PROPOSAL").as_deref()
            != Some(std::ffi::OsStr::new("1"))
    {
        return;
    }
    let Some(root) = std::env::var_os("RUNNE_TEST_PROTECTED_RUNTIME_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    if root.is_absolute()
        && std::fs::symlink_metadata(&root)
            .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
    {
        let marker = root.join(".runne-test-protected-d2-stage");
        let preserve_specific_restart_error = stage == "restart_pre_cycle_projection"
            && std::fs::read_to_string(&marker)
                .is_ok_and(|previous| previous.starts_with("restart_finish_"));
        if !preserve_specific_restart_error {
            let _ = std::fs::write(&marker, stage.as_bytes());
        }
        if std::env::var_os("RUNNE_TEST_D2_KILL_AT_STAGE").as_deref()
            == Some(std::ffi::OsStr::new(stage))
        {
            let _ = std::fs::write(root.join(".runne-test-protected-d2-stage-entered"), stage);
            tokio::task::block_in_place(|| {
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            });
        }
    }
}

#[cfg(all(
    feature = "desktop-protected",
    target_os = "linux",
    not(feature = "test-support")
))]
pub(crate) fn d2_test_stage(_: &'static str) {}
