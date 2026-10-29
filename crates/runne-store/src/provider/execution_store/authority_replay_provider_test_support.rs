include!("authority_replay_root_fixture.rs");
fn upgraded_v25(
    discriminator: u8,
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    ProviderAuthorityIssueRequest,
) {
    upgraded_v25_for_provider(discriminator, "fixture-provider")
}

pub(super) fn upgraded_v25_for_provider(
    discriminator: u8,
    provider: &str,
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    ProviderAuthorityIssueRequest,
) {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let request = super::authority_test_support::prepare_request_for_provider(
        fixture.launch(),
        &fixture.path,
        discriminator,
        provider,
    );
    assert!(matches!(
        fixture.store.issue(fixture.launch(), &request),
        Ok(ProviderAuthorityIssueOutcome::Winner(_))
    ));
    let Fixture {
        directory,
        path,
        store,
        ..
    } = fixture;
    drop(store);
    let connection = Connection::open(&path).unwrap();
    drop_empty_root_binding_fixture(&connection);
    connection
        .execute_batch(
            "DROP TABLE x2_permission_terminal;
             DROP TABLE x2_permission_stop;
             DROP TABLE x2_permission_spent;
             DROP TABLE x2_permission_admission;
             DROP TABLE x2_permission_human;
             DROP TABLE x2_permission_bindings;
             DROP TABLE taskrun_local_permission_routes;
             DROP TRIGGER taskrun_provider_round_bindings_immutable;
             DROP TRIGGER taskrun_provider_round_bindings_no_delete;
             DROP TRIGGER schema_v12_fence_taskrun_provider_round_bindings_insert;
             DROP TRIGGER schema_v12_fence_taskrun_provider_round_bindings_update;
             DROP TRIGGER schema_v12_fence_taskrun_provider_round_bindings_delete;
             DROP TABLE taskrun_provider_round_bindings;
             DROP TRIGGER taskrun_tool_intents_monotonic;
             DROP TRIGGER taskrun_tool_result_immutable;
             DROP TRIGGER taskrun_tool_budget_monotonic;
             DROP TRIGGER taskrun_tool_invocation_binding_immutable;
             DROP TRIGGER taskrun_tool_budgets_no_delete;
             DROP TRIGGER taskrun_tool_invocations_no_delete;
             DROP TRIGGER provider_terminal_application_kinds_immutable;
             DROP TRIGGER provider_terminal_application_kinds_no_delete;
             DROP TRIGGER d2_tool_loop_completions_immutable;
             DROP TRIGGER d2_tool_loop_completions_no_delete;
             DROP TRIGGER schema_v12_fence_d2_tool_loop_completions_insert;
             DROP TRIGGER schema_v12_fence_d2_tool_loop_completions_update;
             DROP TRIGGER schema_v12_fence_d2_tool_loop_completions_delete;
             DROP TABLE d2_tool_loop_completions;
             DROP TRIGGER schema_v12_fence_taskrun_tool_invocations_insert;
             DROP TRIGGER schema_v12_fence_taskrun_tool_invocations_update;
             DROP TRIGGER schema_v12_fence_taskrun_tool_invocations_delete;
             DROP TRIGGER schema_v12_fence_taskrun_tool_budgets_insert;
             DROP TRIGGER schema_v12_fence_taskrun_tool_budgets_update;
             DROP TRIGGER schema_v12_fence_taskrun_tool_budgets_delete;
             DROP TRIGGER schema_v12_fence_provider_terminal_application_kinds_insert;
             DROP TRIGGER schema_v12_fence_provider_terminal_application_kinds_update;
             DROP TRIGGER schema_v12_fence_provider_terminal_application_kinds_delete;
             DROP INDEX idx_taskrun_tool_invocations_state;
             DROP TABLE taskrun_tool_invocations;
             DROP TABLE taskrun_tool_budgets;
             DROP TABLE provider_terminal_application_kinds;
             DROP TRIGGER provider_credential_ticket_insert_issued;
             DROP TRIGGER provider_credential_revoke_irreversible;
             DROP INDEX provider_credential_one_pending_retired_version_cleanup;
             DROP TABLE provider_qualification_admission_fences;
             DROP TABLE credential_cleanup_recovery_attempts;
             DROP TRIGGER provider_credential_attachment_insert;
             DROP TRIGGER provider_credential_attachment_immutable;
             DROP TRIGGER provider_credential_attachment_no_delete;
             DROP TABLE provider_credential_process_attachments;
             DROP TRIGGER provider_credential_verification_binding_insert;
             DROP TRIGGER provider_credential_verification_binding_immutable;
             DROP TRIGGER provider_credential_verification_binding_complete;
             DROP TRIGGER provider_credential_remote_verification_binding;
             ALTER TABLE provider_credential_verification_observations DROP COLUMN readiness_revision;
             ALTER TABLE provider_credential_verification_observations DROP COLUMN release_tuple_digest;
             DROP TRIGGER provider_credential_head_active_lifecycle;
             DROP TRIGGER provider_credential_operation_insert_prepared;
             DROP INDEX provider_credential_one_pending_legacy_source_cleanup;
             DROP INDEX provider_credential_one_non_terminal_operation;
             CREATE UNIQUE INDEX provider_credential_one_non_terminal_operation ON provider_credential_operations(provider_id) WHERE state NOT IN ('COMPLETED', 'FAILED', 'EXPIRED', 'CANCELLED', 'TOMBSTONED');
             DROP TRIGGER provider_credential_qualified_release_tuple_insert;
             DROP TRIGGER provider_credential_qualified_release_tuple_immutable;
             DROP TABLE provider_credential_completion_receipts;
             DROP TRIGGER provider_credential_migration_provenance_insert;
             DROP TRIGGER provider_credential_migration_provenance_immutable;
             DROP TRIGGER provider_credential_claimed_attempt_transition;
             ALTER TABLE provider_credential_operations
                 DROP COLUMN qualified_release_tuple_digest;
             ALTER TABLE provider_credential_operations
                 DROP COLUMN broker_migration_binding_digest;
             ALTER TABLE provider_credential_operations
                 DROP COLUMN claimed_ticket_attempt;
             DROP TABLE provider_online_dispatch_claim_providers;
             DROP TABLE provider_online_dispatch_issuance_evidence;
             DROP TABLE provider_online_credential_effect_bindings;
             DROP TRIGGER schema_v12_fence_provider_secondary_profile_attempts_insert;
             DROP TRIGGER schema_v12_fence_provider_secondary_profile_attempts_update;
             DROP TRIGGER schema_v12_fence_provider_secondary_profile_attempts_delete;
             DROP TRIGGER provider_secondary_profile_attempts_immutable;
             DROP TRIGGER provider_secondary_profile_attempts_no_delete;
             DROP TABLE provider_secondary_profile_attempts;
             DROP TRIGGER schema_v12_fence_provider_secondary_profile_bindings_insert;
             DROP TRIGGER schema_v12_fence_provider_secondary_profile_bindings_update;
             DROP TRIGGER schema_v12_fence_provider_secondary_profile_bindings_delete;
             DROP TRIGGER provider_secondary_profile_bindings_immutable;
             DROP TRIGGER provider_secondary_profile_bindings_no_delete;
             DROP TABLE provider_secondary_profile_bindings;
             DROP TRIGGER schema_v12_fence_provider_secondary_profile_grants_insert;
             DROP TRIGGER schema_v12_fence_provider_secondary_profile_grants_update;
             DROP TRIGGER schema_v12_fence_provider_secondary_profile_grants_delete;
             DROP TRIGGER provider_secondary_profile_grants_identity_immutable;
             DROP TRIGGER provider_secondary_profile_grants_no_delete;
             DROP TABLE provider_secondary_profile_grants;
             DROP TRIGGER taskrun_local_command_stop_receipts_immutable;
             DROP TRIGGER taskrun_local_command_stop_receipts_no_delete;
             DROP TRIGGER schema_v12_fence_taskrun_local_command_stop_receipts_insert;
             DROP TRIGGER schema_v12_fence_taskrun_local_command_stop_receipts_update;
             DROP TRIGGER schema_v12_fence_taskrun_local_command_stop_receipts_delete;
             DROP TABLE taskrun_local_command_stop_receipts;
             DROP TRIGGER schema_v12_fence_taskrun_local_command_attempts_insert;
             DROP TRIGGER schema_v12_fence_taskrun_local_command_attempts_update;
             DROP TRIGGER schema_v12_fence_taskrun_local_command_attempts_delete;
             DROP TRIGGER taskrun_local_command_identity_immutable;
             DROP TRIGGER taskrun_local_command_state_transition;
             DROP TRIGGER taskrun_local_command_no_delete;
             DROP INDEX taskrun_local_command_writer_active;
             DROP TABLE taskrun_local_command_attempts;
             DROP TRIGGER schema_v12_fence_conversation_context_scope_insert;
             DROP TRIGGER schema_v12_fence_conversation_context_scope_update;
             DROP TRIGGER schema_v12_fence_conversation_context_scope_delete;
             DROP TABLE conversation_context_scope;
             DROP TRIGGER schema_v12_fence_execution_nodes_insert;
             DROP TRIGGER schema_v12_fence_execution_nodes_update;
             DROP TRIGGER schema_v12_fence_execution_nodes_delete;
             DROP TABLE execution_nodes;
             DROP TRIGGER schema_v12_fence_taskrun_assignment_occupations_insert;
             DROP TRIGGER schema_v12_fence_taskrun_assignment_occupations_update;
             DROP TRIGGER schema_v12_fence_taskrun_assignment_occupations_delete;
             DROP TRIGGER schema_v12_fence_taskrun_assignment_lease_renewals_insert;
             DROP TRIGGER schema_v12_fence_taskrun_assignment_lease_renewals_update;
             DROP TRIGGER schema_v12_fence_taskrun_assignment_lease_renewals_delete;
             DROP TRIGGER taskrun_assignment_lease_renewals_immutable;
             DROP TRIGGER taskrun_assignment_lease_renewals_no_delete;
             DROP TRIGGER taskrun_dispatch_intents_immutable;
             DROP TRIGGER taskrun_dispatch_intents_no_delete;
             DROP TRIGGER taskrun_occupation_intent_guard;
             DROP TRIGGER taskrun_provider_bindings_immutable;
             DROP TRIGGER taskrun_provider_bindings_no_delete;
             DROP TABLE taskrun_provider_bindings;
             DROP TRIGGER text_only_taskrun_lineage_immutable;
             DROP TRIGGER text_only_taskrun_lineage_no_delete;
             DROP TRIGGER text_only_taskrun_lineage_no_workspace_collision;
             DROP TRIGGER schema_v12_fence_text_only_taskrun_lineage_insert;
             DROP TRIGGER schema_v12_fence_text_only_taskrun_lineage_update;
             DROP TRIGGER schema_v12_fence_text_only_taskrun_lineage_delete;
             DROP TABLE text_only_taskrun_lineage;
             DROP TABLE conversation_writer_leases;
             DROP TRIGGER provider_terminal_dispositions_immutable;
             DROP TRIGGER provider_terminal_dispositions_no_delete;
             DROP TRIGGER schema_v12_fence_provider_terminal_dispositions_insert;
             DROP TRIGGER schema_v12_fence_provider_terminal_dispositions_update;
             DROP TRIGGER schema_v12_fence_provider_terminal_dispositions_delete;
             DROP TABLE provider_terminal_dispositions;
             DROP TRIGGER taskrun_terminal_settlement_immutable;
             DROP TRIGGER taskrun_terminal_settlement_no_delete;
             DROP TRIGGER schema_v12_fence_taskrun_terminal_settlement_receipts_insert;
             DROP TRIGGER schema_v12_fence_taskrun_terminal_settlement_receipts_update;
             DROP TRIGGER schema_v12_fence_taskrun_terminal_settlement_receipts_delete;
             DROP TABLE taskrun_terminal_settlement_receipts;
             DROP TABLE taskrun_dispatch_intents;
             DROP TRIGGER global_command_id_from_release_v45;
             DROP TRIGGER global_command_id_from_command_receipts_v45;
             DROP TRIGGER global_command_id_from_project_workspace_receipts_v45;
             DROP TRIGGER global_command_id_from_taskrun_claim_receipts_v45;
             DROP TRIGGER global_command_id_from_lease_renewals_v45;
             DROP TRIGGER taskrun_no_effect_release_immutable;
             DROP TRIGGER taskrun_no_effect_release_no_delete;
             DROP TABLE taskrun_no_effect_release_receipts;
             DROP TRIGGER global_command_id_from_lease_renewals_v43;
             DROP TRIGGER global_command_id_from_command_receipts_v43;
             DROP TRIGGER global_command_id_from_project_workspace_receipts_v43;
             DROP TRIGGER global_command_id_from_taskrun_claim_receipts_v43;
             DROP TABLE taskrun_assignment_lease_renewals;
             DROP TABLE taskrun_assignment_occupations;
             DROP TABLE taskrun_unknown_successor_receipts;
             DROP TRIGGER taskrun_provider_cancel_fences_immutable;
             DROP TRIGGER taskrun_provider_cancel_fences_no_delete;
             DROP TRIGGER schema_v12_fence_taskrun_provider_cancel_fences_insert;
             DROP TRIGGER schema_v12_fence_taskrun_provider_cancel_fences_update;
             DROP TRIGGER schema_v12_fence_taskrun_provider_cancel_fences_delete;
             DROP TABLE taskrun_provider_cancel_fences;
             DROP TABLE provider_remote_terminal_audit_receipts;
             DROP TABLE provider_remote_terminal_applications;
             DROP TABLE provider_remote_artifact_cancel_closures;
             DROP TABLE provider_remote_terminal_settlements;
             DROP TABLE provider_remote_terminal_artifacts;
             DROP TABLE provider_remote_operation_proofs;
             DROP TABLE provider_remote_response_bindings;
             DROP TABLE provider_remote_request_intents;
             DROP TABLE provider_unknown_terminal_receipts;
             DROP TRIGGER global_command_id_from_command_receipts_v42;
             DROP TRIGGER global_command_id_from_project_workspace_receipts_v42;
             DROP TABLE taskrun_claim_receipts;
             DROP TABLE taskrun_assignments;
             DROP TABLE taskrun_fence_counters;
             DELETE FROM schema_version WHERE version >= 26;",
    )
        .unwrap();
    restore_v36_accounting_for_fixture(&connection).unwrap();
    connection
        .execute("DROP TABLE provider_subscription_budgets", [])
        .unwrap();
    crate::schema::restore_v18_project_workspace_receipt_for_test(&connection).unwrap();
    // V39 rebuilt the lineage table with the submit origin; the historical
    // V25 validators pin the V18 shape, so rebuild it from the frozen DDL.
    crate::schema::restore_v18_taskrun_lineage_for_test(&connection).unwrap();
    crate::schema::restore_v25_credential_triggers_for_test(&connection).unwrap();
    connection
        .execute_batch(
            "DROP TABLE permission_mode_command_receipt_managed_identity;
             DROP TABLE permission_mode_native_challenge_managed_identity;
             DROP TABLE taskrun_tool_permission_admissions;
             DROP TABLE permission_mode_native_challenges;
             DROP TABLE permission_mode_command_receipts;
             DROP TRIGGER IF EXISTS command_receipt_id_global_d21;
             DROP TRIGGER IF EXISTS project_workspace_receipt_id_global_d21;
             DROP TABLE permission_mode_selections;",
        )
        .unwrap();
    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        25
    );
    let released_schema_objects: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE (name IN ('d2_tool_loop_completions','d2_tool_loop_completions_immutable','d2_tool_loop_completions_no_delete','schema_v12_fence_d2_tool_loop_completions_insert','schema_v12_fence_d2_tool_loop_completions_update','schema_v12_fence_d2_tool_loop_completions_delete','taskrun_provider_round_bindings','taskrun_provider_round_bindings_immutable','taskrun_provider_round_bindings_no_delete','schema_v12_fence_taskrun_provider_round_bindings_insert','schema_v12_fence_taskrun_provider_round_bindings_update','schema_v12_fence_taskrun_provider_round_bindings_delete','taskrun_tool_invocations','taskrun_tool_budgets','provider_terminal_application_kinds','taskrun_tool_intents_monotonic','taskrun_tool_result_immutable','taskrun_tool_budget_monotonic','taskrun_tool_invocation_binding_immutable','taskrun_tool_budgets_no_delete','taskrun_tool_invocations_no_delete','provider_terminal_application_kinds_immutable','provider_terminal_application_kinds_no_delete','idx_taskrun_tool_invocations_state','taskrun_provider_bindings', 'taskrun_provider_bindings_immutable', 'taskrun_provider_bindings_no_delete', 'text_only_taskrun_lineage', 'text_only_taskrun_lineage_immutable', 'text_only_taskrun_lineage_no_delete', 'text_only_taskrun_lineage_no_workspace_collision', 'taskrun_terminal_settlement_receipts', 'taskrun_terminal_settlement_immutable', 'taskrun_terminal_settlement_no_delete', 'schema_v12_fence_taskrun_terminal_settlement_receipts_insert', 'schema_v12_fence_taskrun_terminal_settlement_receipts_update', 'schema_v12_fence_taskrun_terminal_settlement_receipts_delete', 'provider_terminal_dispositions', 'provider_terminal_dispositions_immutable', 'provider_terminal_dispositions_no_delete', 'schema_v12_fence_provider_terminal_dispositions_insert', 'schema_v12_fence_provider_terminal_dispositions_update', 'schema_v12_fence_provider_terminal_dispositions_delete', 'provider_secondary_profile_grants', 'provider_secondary_profile_grants_identity_immutable', 'provider_secondary_profile_grants_no_delete', 'provider_secondary_profile_bindings', 'provider_secondary_profile_bindings_immutable', 'provider_secondary_profile_bindings_no_delete', 'provider_secondary_profile_bindings_one_active', 'provider_secondary_profile_attempts', 'provider_secondary_profile_attempts_immutable', 'provider_secondary_profile_attempts_no_delete', 'taskrun_local_command_attempts', 'taskrun_local_command_writer_active', 'taskrun_local_command_identity_immutable', 'taskrun_local_command_state_transition', 'taskrun_local_command_no_delete', 'schema_v12_fence_taskrun_local_command_attempts_insert', 'schema_v12_fence_taskrun_local_command_attempts_update', 'schema_v12_fence_taskrun_local_command_attempts_delete', 'taskrun_local_command_stop_receipts', 'taskrun_local_command_stop_receipts_immutable', 'taskrun_local_command_stop_receipts_no_delete', 'schema_v12_fence_taskrun_local_command_stop_receipts_insert', 'schema_v12_fence_taskrun_local_command_stop_receipts_update', 'schema_v12_fence_taskrun_local_command_stop_receipts_delete', 'taskrun_unknown_successor_receipts', 'provider_remote_terminal_audit_receipts', 'provider_remote_terminal_audit_receipts_immutable', 'provider_remote_terminal_audit_receipts_no_delete', 'schema_v12_fence_provider_remote_terminal_audit_receipts_insert', 'schema_v12_fence_provider_remote_terminal_audit_receipts_update', 'schema_v12_fence_provider_remote_terminal_audit_receipts_delete', 'provider_remote_terminal_applications', 'provider_remote_artifact_cancel_closures', 'provider_remote_terminal_settlements', 'provider_remote_terminal_artifacts', 'provider_remote_operation_proofs', 'provider_remote_response_bindings', 'provider_remote_request_intents', 'provider_unknown_terminal_receipts') OR name LIKE 'permission_mode_%' OR name LIKE 'schema_v12_fence_permission_mode_%' OR name LIKE 'taskrun_tool_permission_admission%' OR name LIKE 'schema_v12_fence_taskrun_tool_permission_admissions_%')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        released_schema_objects, 0,
        "V25 fixture must not retain later schema objects"
    );
    let released_v68_objects: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master
             WHERE name LIKE 'taskrun_local_permission_routes%'
                OR name LIKE 'x2_permission_%'
                OR name LIKE 'schema_v12_fence_taskrun_local_permission_routes_%'
                OR name LIKE 'schema_v12_fence_x2_permission_%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        released_v68_objects, 0,
        "V25 fixture must not retain V68 local permission objects"
    );
    drop(
        crate::schema::reopen_managed_connection_validated(
            &path,
            crate::schema::ConnectionMode::ValidatedReopen,
            |_| Ok(()),
        )
        .expect("reconstructed V25 fixture must pass its real admission validators"),
    );
    drop(connection);

    (directory, path, request)
}

include!("authority_replay_provider_test_support/restore_v36.rs");
