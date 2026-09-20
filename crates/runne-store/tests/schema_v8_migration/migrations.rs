// ── v6 → v8 upgrade path ────────────────────────────────────────────────

#[test]
fn v6_to_v8_migration() {
    let conn = fresh_v8_db();
    conn.execute_batch(
        "DROP TRIGGER global_command_id_from_command_receipts;
         DROP TRIGGER global_command_id_from_project_workspace_receipts;
         DROP TABLE task_run_workspace_lineage;
         DROP TABLE workspace_identity_history;
         DROP TABLE root_admission_nonces;
         DROP TABLE project_workspace_command_receipts;
         DROP TABLE workspaces;
         DROP TABLE projects;",
    )
    .unwrap();
    drop_v17_snapshots(&conn);
    drop_v12_fences(&conn);
    drop_v13_provider_execution(&conn);
    conn.execute_batch(
        "DROP TABLE provider_effect_authorities;
         DROP TABLE provider_dispatch_attempts;
         DROP TABLE provider_prepared_requests;
         DROP TABLE schema_lineage;
         DROP TABLE consumption_intents;
         DROP TABLE verification_evidence;
         DROP TABLE _replay_subscriptions;
         DROP TABLE _daemon_info;
         DROP TABLE _authority;
         DROP TABLE security_permit_claims;
         DROP TABLE security_audit_pre_effect;
         DROP TABLE security_budget_consumptions;
         DROP TABLE security_authorization_decisions;
         DROP TABLE security_dispatch_intents;
         DROP TABLE process_output;
         DROP INDEX idx_process_registry_owner;
         DROP TABLE process_registry;
         DROP INDEX idx_approvals_pending;
         DROP TABLE approvals;
         DROP TRIGGER IF EXISTS schema_v12_fence_conversation_context_scope_insert;
         DROP TRIGGER IF EXISTS schema_v12_fence_conversation_context_scope_update;
         DROP TRIGGER IF EXISTS schema_v12_fence_conversation_context_scope_delete;
         DROP TABLE IF EXISTS conversation_context_scope;
         DELETE FROM schema_version WHERE version >= 7;",
    )
    .unwrap();

    // Apply remaining migrations (v7, v8)
    apply_migrations(&conn).unwrap();

    // Verify v7 tables
    for table in [
        "security_dispatch_intents",
        "security_authorization_decisions",
        "security_budget_consumptions",
        "security_audit_pre_effect",
        "security_permit_claims",
    ] {
        assert!(table_exists(&conn, table), "missing v7 table {table}");
    }

    // Verify v8 tables
    for table in ["_authority", "_daemon_info", "_replay_subscriptions"] {
        assert!(table_exists(&conn, table), "missing v8 table {table}");
    }

    let version: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(version, CURRENT_SCHEMA_VERSION);
}
