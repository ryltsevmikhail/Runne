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
    connection
        .execute_batch(
            "DROP TRIGGER provider_credential_ticket_insert_issued;
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
             DROP TRIGGER global_command_id_from_lease_renewals_v43;
             DROP TRIGGER global_command_id_from_command_receipts_v43;
             DROP TRIGGER global_command_id_from_project_workspace_receipts_v43;
             DROP TRIGGER global_command_id_from_taskrun_claim_receipts_v43;
             DROP TABLE taskrun_assignment_lease_renewals;
             DROP TABLE taskrun_assignment_occupations;
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
    assert_eq!(
        connection
            .query_row("SELECT MAX(version) FROM schema_version", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        25
    );
    drop(connection);

    (directory, path, request)
}

fn restore_v36_accounting_for_fixture(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA legacy_alter_table=ON;")?;
    for (table, current, old) in [
        (
            "provider_execution_admissions",
            "max_cost_micros INTEGER NOT NULL CHECK(max_cost_micros >= 0), currency TEXT NOT NULL CHECK(length(currency) = 3 AND (max_cost_micros > 0 OR currency = 'XXX'))",
            "max_cost_micros INTEGER NOT NULL CHECK(max_cost_micros > 0), currency TEXT NOT NULL CHECK(length(currency) = 3)",
        ),
        (
            "provider_budget_reservations",
            "amount INTEGER NOT NULL CHECK(amount > 0 OR (dimension = 2 AND amount = 0))",
            "amount INTEGER NOT NULL CHECK(amount > 0)",
        ),
    ] {
        let source: String = connection.query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
            [table],
            |row| row.get(0),
        )?;
        let objects: Vec<String> = connection
            .prepare("SELECT sql FROM sqlite_master WHERE tbl_name=?1 AND type IN ('index','trigger') AND sql IS NOT NULL ORDER BY type,name")?
            .query_map([table], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let old_table = format!("{table}_v37");
        connection.execute(&format!("ALTER TABLE {table} RENAME TO {old_table}"), [])?;
        let rewritten = source.replace(current, old);
        connection.execute_batch(&rewritten)?;
        connection.execute(
            &format!("INSERT INTO {table} SELECT * FROM {old_table}"),
            [],
        )?;
        connection.execute(&format!("DROP TABLE {old_table}"), [])?;
        for sql in objects {
            connection.execute_batch(&sql)?;
        }
    }
    connection.execute_batch("PRAGMA legacy_alter_table=OFF; PRAGMA foreign_keys=ON;")?;
    Ok(())
}

fn admission_fields(path: &std::path::Path) -> (Vec<u8>, Vec<u8>, i64, i64) {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT dispatch_attempt_id, authority_id, authority_revision, issued_at
             FROM provider_execution_admissions",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap()
}

fn admission_counts(path: &std::path::Path) -> (i64, i64) {
    Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM provider_execution_admissions),
                    (SELECT COUNT(*) FROM provider_online_dispatch_claim_providers)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}
