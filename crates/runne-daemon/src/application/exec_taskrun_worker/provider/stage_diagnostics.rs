pub(crate) fn d2_stage(stage: &'static str) {
    #[cfg(all(
        feature = "desktop-protected",
        target_os = "linux",
        feature = "test-support"
    ))]
    {
        const ALLOWED: &[&str] = &[
            "provider_round_start",
            "provider_rejected",
            "provider_remote_failed",
            "provider_remote_incomplete",
            "provider_uncertain",
            "provider_policy_denied",
            "provider_unavailable",
            "provider_conflict",
            "final_text_start",
            "final_text_error",
            "final_text_key_unavailable",
            "final_text_key_retention_unsupported",
            "final_text_journal_corrupt",
            "final_text_persistence_unavailable",
            "final_text_adapter_unavailable",
            "final_text_commit_lost",
            "final_text_recovery_frozen",
            "final_text_terminal_rejected",
            "final_text_policy_denied",
            "final_text_pricing_unavailable",
            "final_text_application_unavailable",
            "final_text_application_conflict",
            "final_text_invalid_utf8",
            "final_text_tool_profile_unavailable",
            "final_text_profile_mismatch",
            "final_text_recovered",
            "current_targets_start",
            "current_targets_error",
            "current_targets_valid",
            "evaluation_start",
            "evaluation_error",
            "evaluation_ready",
            "complete_cycle_start",
            "complete_cycle_error",
            "cycle_completed",
            "conversation_projection_start",
            "conversation_projection_error",
            "conversation_projected",
            "proposal_received",
            "final_stop_received",
            "proposal_persist_start",
            "proposal_persist_error",
            "proposal_persisted",
            "proposal_validating",
            "proposal_encrypted",
            "proposal_durable",
            "approval_pending",
            "approval_approved",
            "approval_denied",
            "native_effect_recorded",
            "effect_epoch_check",
            "effect_open_arguments",
            "effect_target_admission",
            "effect_target_snapshot",
            "effect_trust_lease",
            "effect_claim",
            "effect_area_create",
            "effect_command_access",
            "effect_command_missing",
            "effect_command_policy",
            "effect_command_other",
            "effect_area_recorded",
            "effect_area_remove_failed",
            "effect_helper_preflight",
            "effect_helper_preflight_ok",
            "effect_helper_input",
            "effect_helper_exe_open",
            "effect_helper_seal",
            "effect_helper_preflight",
            "effect_helper_spawn",
            "effect_helper_gate_release",
            "effect_helper_gate_failed",
            "effect_helper_supervise",
            "effect_helper_complete",
            "effect_helper_stopped",
            "effect_helper_supervisor_error",
            "proposal_error_root_admission",
            "proposal_error_managed_policy",
            "proposal_error_permission_prepare",
            "permission_managed",
            "permission_effective",
            "permission_native",
            "permission_compiler",
            "proposal_error_helper_prepare",
            "proposal_error_arguments",
            "proposal_error_sources",
            "proposal_sources_validated",
            "proposal_error_taskrun_read",
            "proposal_error_head",
            "proposal_error_cycle",
            "proposal_error_target_capture",
            "proposal_target_captured",
            "proposal_error_encrypt",
            "proposal_store_conflict",
            "proposal_store_binding_conflict",
            "proposal_store_sources_conflict",
            "proposal_store_duplicate_effect",
            "proposal_store_effect_digest_tool_mismatch",
            "proposal_store_effect_digest_arguments_mismatch",
            "proposal_store_effect_digest_target_mismatch",
            "proposal_store_effect_digest_root_mismatch",
            "proposal_store_payload_nonce",
            "proposal_store_insert_unique",
            "proposal_store_insert_check",
            "proposal_store_insert_foreign_key",
            "proposal_store_insert_other",
            "proposal_store_stale",
            "proposal_store_invalid_state",
            "proposal_store_approval_denied",
            "proposal_store_approval_expired",
            "proposal_store_budget_exhausted",
            "proposal_store_cancelled",
            "proposal_store_uncertain",
            "proposal_store_corrupt",
            "proposal_store_unavailable",
        ];
        if !ALLOWED.contains(&stage)
            || ![
                "RUNNE_TEST_D2_TOOL_PROPOSAL",
                "RUNNE_TEST_TERMINAL_AGENT_FIXTURE",
            ]
            .iter()
            .any(|key| std::env::var_os(key).as_deref() == Some(std::ffi::OsStr::new("1")))
        {
            return;
        }
        if let Some(root) = std::env::var_os("RUNNE_TEST_PROTECTED_RUNTIME_ROOT") {
            let root = std::path::PathBuf::from(root);
            if root.is_absolute() && root.is_dir() && !root.is_symlink() {
                let marker = root.join(".runne-test-protected-d2-stage");
                // A provider uncertainty can retain an earlier proposal/effect
                // diagnostic below, but its exact crash barrier must still be
                // reachable after the durable dispatch has become uncertain.
                if stage == "provider_uncertain"
                    && std::env::var_os("RUNNE_TEST_D2_KILL_AT_STAGE").as_deref()
                        == Some(std::ffi::OsStr::new(stage))
                {
                    let _ = std::fs::write(&marker, stage.as_bytes());
                    let _ = std::fs::write(
                        root.join(".runne-test-protected-d2-stage-entered"),
                        stage.as_bytes(),
                    );
                    tokio::task::block_in_place(|| {
                        loop {
                            std::thread::sleep(std::time::Duration::from_millis(10));
                        }
                    });
                }
                if (stage.starts_with("provider_") && stage != "provider_round_start")
                    || stage == "proposal_error_permission_prepare"
                {
                    let preserve = std::fs::read_to_string(&marker).is_ok_and(|previous| {
                        previous.starts_with("permission_")
                            || previous.starts_with("effect_")
                            || previous.starts_with("proposal_")
                            || previous.starts_with("final_text_")
                            || previous.starts_with("current_targets_")
                            || previous.starts_with("evaluation_")
                            || previous.starts_with("complete_cycle_")
                            || previous.starts_with("conversation_projection_")
                    });
                    if preserve {
                        return;
                    }
                }
                let _ = std::fs::write(marker, stage.as_bytes());
                if std::env::var_os("RUNNE_TEST_D2_KILL_AT_STAGE").as_deref()
                    == Some(std::ffi::OsStr::new(stage))
                {
                    let _ = std::fs::write(
                        root.join(".runne-test-protected-d2-stage-entered"),
                        stage.as_bytes(),
                    );
                    loop {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                }
            }
        }
    }
    #[cfg(not(all(
        feature = "desktop-protected",
        target_os = "linux",
        feature = "test-support"
    )))]
    let _ = stage;
}
