include!("migrations/v64_taskrun_tool_invocation.rs");
include!("migrations/v65_permission_modes.rs");
include!("migrations/v66_permission_confirmation.rs");
include!("migrations/v67_permission_managed_identity.rs");
include!("migrations/v68_taskrun_permission.rs");
include!("migrations/v68_terminal_reopen_match.rs");
include!("migrations/v69_permission_retained_context.rs");
include!("taskrun_permission.rs");
#[cfg(feature = "test-support")]
include!("test_support_matcher_diagnosis.rs");
mod project_workspace_backfill;
mod project_workspace_schema;
#[cfg(test)]
pub(crate) mod project_workspace_test_helpers;
#[cfg(test)]
pub(crate) use project_workspace_schema::restore_v18_project_workspace_receipt_for_test;
#[cfg(test)]
pub(crate) use project_workspace_test_helpers::restore_v18_taskrun_lineage_for_test;
pub(crate) mod provider_schema;
pub mod recovery_diagnosis;
mod replay_promotion_snapshot_schema;
mod replay_snapshot_schema;
include!("open.rs");
include!("authority_identity.rs");
include!("authority_launch.rs");
include!("replay.rs");

#[cfg(test)]
pub(crate) fn restore_v25_credential_triggers_for_test(
    connection: &Connection,
) -> SqliteResult<()> {
    let ticket_trigger = V24_TRIGGERS
        .iter()
        .find(|(name, _)| *name == "provider_credential_ticket_insert_issued")
        .expect("V24 ticket trigger exists")
        .1;
    connection.execute_batch(&v25_trigger(
        "provider_credential_ticket_insert_issued",
        ticket_trigger,
    ))?;
    let insert_trigger = V24_TRIGGERS
        .iter()
        .find(|(name, _)| *name == "provider_credential_operation_insert_prepared")
        .expect("V24 insert trigger exists")
        .1;
    connection.execute_batch(&v25_trigger(
        "provider_credential_operation_insert_prepared",
        insert_trigger,
    ))?;
    connection.execute_batch(v24_head_active_lifecycle_trigger())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    const TEST_ID: [u8; 16] = [0x42; 16];

    fn initialize_v1(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )
        .unwrap();
        conn.execute_batch(MIGRATION_V1).unwrap();
        conn.execute("INSERT INTO schema_version (version) VALUES (1)", [])
            .unwrap();
    }

    include!("tests/admission.rs");
    include!("tests/actual_handle_identity.rs");
    include!("tests/linux_wal_identity_locks.rs");
    include!("tests/windows_live_wal.rs");
    include!("tests/dacl_isolation_windows.rs");
    include!("tests/windows_v39_v40_live_wal.rs");
    include!("tests/windows_post_v40_scope_admission.rs");
    include!("tests/migrations.rs");
    include!("tests/released.rs");
    include!("tests/v42_taskrun_claim.rs");
    include!("tests/v43_taskrun_occupation.rs");
    include!("tests/v44_taskrun_dispatch_intent.rs");
    include!("tests/v45_taskrun_no_effect_release.rs");
    include!("tests/v46_taskrun_provider_binding.rs");
    include!("tests/v47_text_only_taskrun_lineage.rs");
    include!("tests/v49_taskrun_terminal_settlement.rs");
    include!("tests/v50_provider_terminal_disposition.rs");
    include!("tests/v51_taskrun_local_command.rs");
    include!("tests/v52_secondary_profile_grants.rs");
    include!("tests/v53_taskrun_local_stop_receipt.rs");
    include!("tests/v54_provider_remote_response_binding.rs");
    include!("tests/v55_provider_remote_terminal_artifact.rs");
    include!("tests/v56_provider_cancel_fence.rs");
    include!("tests/v57_taskrun_unknown_successor.rs");
    include!("tests/v58_provider_remote_operation_proof.rs");
    include!("tests/v59_remote_terminal_settlement.rs");
    include!("tests/v60_remote_artifact_cancel_closure.rs");
    include!("tests/v61_remote_terminal_application.rs");
    include!("tests/v64_tool_invocation.rs");
    include!("tests/v65_permission_modes.rs");
    include!("tests/v66_permission_confirmation.rs");
    #[path = "v67_permission_managed_identity.rs"]
    mod v67_permission_managed_identity;
    include!("tests/permission_schema_modules.rs");
    include!("tests/v68_permission_terminal_reopen.rs");
    include!("tests/recovery_compatibility.rs");
    include!("tests/recovery_compatibility_v24.rs");
    include!("tests/credential_v24.rs");
    include!("tests/credential_v24_invariants.rs");
    include!("tests/credential_v24_observation_invariants.rs");
    include!("tests/credential_v24_legacy_corruption.rs");
    include!("tests/credential_v24_active_invariants.rs");
    include!("tests/credential_v24_target_invariants.rs");
    include!("tests/credential_v24_shape_invariants.rs");
    include!("tests/credential_v24_owner_invariants.rs");
    include!("tests/credential_v24_verification_ref_invariants.rs");
    include!("tests/credential_v25.rs");
    include!("tests/credential_v26.rs");
    include!("tests/credential_v27.rs");
    include!("tests/credential_v28.rs");
    include!("tests/credential_v29.rs");
    include!("tests/credential_v30.rs");
    include!("tests/credential_v32.rs");
    include!("tests/credential_v33.rs");
    include!("tests/credential_v35.rs");
    include!("tests/credential_v35_adversarial.rs");
    include!("tests/credential_v36.rs");
    include!("tests/project_workspace_v36.rs");
    include!("tests/project_workspace_v39.rs");
    include!("tests/conversation_context_scope_v40.rs");
    include!("tests/frozen_migrations.rs");
    include!("tests/provider_accounting_v37.rs");
}

include!("migrations/v70_workspace_root_identity.rs");

include!("migrations/v71_coding_tool_budget.rs");
