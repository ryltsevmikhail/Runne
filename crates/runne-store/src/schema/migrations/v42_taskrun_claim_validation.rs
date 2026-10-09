pub(super) fn v42_structure_matches(
    connection: &Connection,
    include_v43_extensions: bool,
) -> SqliteResult<bool> {
    let marker: (i64, i64, i64, i64) = connection.query_row(
        "SELECT COALESCE(MAX(version),0),COALESCE(MIN(version),0),COUNT(*),COALESCE(SUM(version),0) FROM schema_version",
        [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    let marker_matches = if include_v43_extensions {
        matches!(
            marker,
            (43, 1, 42, 927)
                | (43, 1, 43, 946)
                | (44, 1, 43, 971)
                | (44, 1, 44, 990)
                | (45, 1, 44, 1016)
                | (45, 1, 45, 1035)
                | (46, 1, 45, 1062)
                | (46, 1, 46, 1081)
                | (47, 1, 46, 1109)
                | (47, 1, 47, 1128)
                | (48, 1, 47, 1157)
                | (48, 1, 48, 1176)
                | (49, 1, 48, 1206)
                | (49, 1, 49, 1225)
                | (50, 1, 49, 1256)
                | (50, 1, 50, 1275)
                | (51, 1, 50, 1307)
                | (51, 1, 51, 1326)
                | (52, 1, 51, 1359)
                | (52, 1, 52, 1378)
                | (53, 1, 52, 1412)
                | (53, 1, 53, 1431)
                | (54, 1, 53, 1466)
                | (54, 1, 54, 1485)
                | (55, 1, 54, 1521)
                | (55, 1, 55, 1540)
                | (56, 1, 55, 1577)
                | (56, 1, 56, 1596)
                | (57, 1, 56, 1634)
                | (57, 1, 57, 1653)
                | (58, 1, 57, 1692)
                | (58, 1, 58, 1711)
                | (59, 1, 58, 1751)
                | (59, 1, 59, 1770)
                | (60, 1, 59, 1811)
                | (60, 1, 60, 1830)
                | (61, 1, 60, 1872)
                | (61, 1, 61, 1891)
                | (62, 1, 61, 1934)
                | (62, 1, 62, 1953)
                | (63, 1, 62, 1997)
                | (63, 1, 63, 2016)
                | (64, 1, 63, 2061)
                | (64, 1, 64, 2080)
                | (65, 1, 64, 2126)
                | (65, 1, 65, 2145)
                | (66, 1, 65, 2192)
                | (66, 1, 66, 2211)
                | (67, 1, 66, 2259)
                | (67, 1, 67, 2278)
                | (68, 1, 67, 2327)
                | (68, 1, 68, 2346)
        )
    } else {
        matches!(marker, (42, 1, 41, 884) | (42, 1, 42, 903))
    };
    if !marker_matches {
        return Ok(false);
    }
    let mut tables = vec![
        V33_TABLE,
        V35_TABLE,
        TABLE,
        "conversation_context_scope",
        "execution_nodes",
        "taskrun_fence_counters",
        "taskrun_assignments",
        "taskrun_claim_receipts",
    ];
    let mut indexes = vec![V33_INDEX, "taskrun_assignments_live_node"];
    let mut triggers = Vec::new();
    if include_v43_extensions {
        tables.extend([
            "taskrun_assignment_occupations",
            "taskrun_assignment_lease_renewals",
        ]);
        indexes.push("taskrun_assignment_occupations_capacity");
        triggers.extend([
            (
                "taskrun_assignment_lease_renewals_immutable",
                "CREATE TRIGGER taskrun_assignment_lease_renewals_immutable BEFORE UPDATE ON taskrun_assignment_lease_renewals BEGIN SELECT RAISE(ABORT, 'TaskRun lease renewal receipt is append only'); END",
            ),
            (
                "taskrun_assignment_lease_renewals_no_delete",
                "CREATE TRIGGER taskrun_assignment_lease_renewals_no_delete BEFORE DELETE ON taskrun_assignment_lease_renewals BEGIN SELECT RAISE(ABORT, 'TaskRun lease renewal receipt is append only'); END",
            ),
        ]);
    }
    if marker.0 >= 44 {
        tables.push("taskrun_dispatch_intents");
        triggers.extend([
            ("taskrun_dispatch_intents_immutable", "CREATE TRIGGER taskrun_dispatch_intents_immutable BEFORE UPDATE ON taskrun_dispatch_intents BEGIN SELECT RAISE(ABORT,'dispatch intent is append only'); END"),
            ("taskrun_dispatch_intents_no_delete", "CREATE TRIGGER taskrun_dispatch_intents_no_delete BEFORE DELETE ON taskrun_dispatch_intents BEGIN SELECT RAISE(ABORT,'dispatch intent is append only'); END"),
            ("taskrun_occupation_intent_guard", "CREATE TRIGGER taskrun_occupation_intent_guard BEFORE UPDATE OF dispatch_intent ON taskrun_assignment_occupations WHEN (NEW.dispatch_intent='present' AND NOT EXISTS(SELECT 1 FROM taskrun_dispatch_intents i WHERE i.taskrun_id=NEW.taskrun_id AND i.fence=NEW.fence AND i.attempt_id=NEW.attempt_id AND i.node_id=NEW.node_id AND i.node_epoch=NEW.node_epoch AND i.state='present')) OR (OLD.dispatch_intent IN ('present','unknown') AND NEW.dispatch_intent!=OLD.dispatch_intent) BEGIN SELECT RAISE(ABORT,'dispatch intent evidence mismatch'); END"),
        ]);
    }
    if marker.0 >= 45 {
        tables.push("taskrun_no_effect_release_receipts");
        triggers.extend([
            ("taskrun_no_effect_release_immutable", "CREATE TRIGGER taskrun_no_effect_release_immutable BEFORE UPDATE ON taskrun_no_effect_release_receipts BEGIN SELECT RAISE(ABORT,'no-effect release receipt is append only'); END"),
            ("taskrun_no_effect_release_no_delete", "CREATE TRIGGER taskrun_no_effect_release_no_delete BEFORE DELETE ON taskrun_no_effect_release_receipts BEGIN SELECT RAISE(ABORT,'no-effect release receipt is append only'); END"),
            ("global_command_id_from_release_v45", "CREATE TRIGGER global_command_id_from_release_v45 BEFORE INSERT ON taskrun_no_effect_release_receipts WHEN EXISTS(SELECT 1 FROM command_receipts WHERE command_id=NEW.command_id) OR EXISTS(SELECT 1 FROM project_workspace_command_receipts WHERE command_id=NEW.command_id) OR EXISTS(SELECT 1 FROM taskrun_claim_receipts WHERE command_id=NEW.command_id) OR EXISTS(SELECT 1 FROM taskrun_assignment_lease_renewals WHERE renewal_id=NEW.command_id) BEGIN SELECT RAISE(ABORT,'global command id collision'); END"),
            ("global_command_id_from_command_receipts_v45", "CREATE TRIGGER global_command_id_from_command_receipts_v45 BEFORE INSERT ON command_receipts WHEN EXISTS(SELECT 1 FROM taskrun_no_effect_release_receipts WHERE command_id=NEW.command_id) BEGIN SELECT RAISE(ABORT,'global command id collision'); END"),
            ("global_command_id_from_project_workspace_receipts_v45", "CREATE TRIGGER global_command_id_from_project_workspace_receipts_v45 BEFORE INSERT ON project_workspace_command_receipts WHEN EXISTS(SELECT 1 FROM taskrun_no_effect_release_receipts WHERE command_id=NEW.command_id) BEGIN SELECT RAISE(ABORT,'global command id collision'); END"),
            ("global_command_id_from_taskrun_claim_receipts_v45", "CREATE TRIGGER global_command_id_from_taskrun_claim_receipts_v45 BEFORE INSERT ON taskrun_claim_receipts WHEN EXISTS(SELECT 1 FROM taskrun_no_effect_release_receipts WHERE command_id=NEW.command_id) BEGIN SELECT RAISE(ABORT,'global command id collision'); END"),
            ("global_command_id_from_lease_renewals_v45", "CREATE TRIGGER global_command_id_from_lease_renewals_v45 BEFORE INSERT ON taskrun_assignment_lease_renewals WHEN EXISTS(SELECT 1 FROM taskrun_no_effect_release_receipts WHERE command_id=NEW.renewal_id) BEGIN SELECT RAISE(ABORT,'global command id collision'); END"),
        ]);
    }
    if marker.0 >= 46 {
        tables.push("taskrun_provider_bindings");
        triggers.extend([
            ("taskrun_provider_bindings_immutable", "CREATE TRIGGER taskrun_provider_bindings_immutable BEFORE UPDATE ON taskrun_provider_bindings BEGIN SELECT RAISE(ABORT,'TaskRun provider binding is append only'); END"),
            ("taskrun_provider_bindings_no_delete", "CREATE TRIGGER taskrun_provider_bindings_no_delete BEFORE DELETE ON taskrun_provider_bindings BEGIN SELECT RAISE(ABORT,'TaskRun provider binding is append only'); END"),
        ]);
    }
    if marker.0 >= 48 {
        tables.push("conversation_writer_leases");
    }
    if marker.0 >= 49 {
        tables.push("taskrun_terminal_settlement_receipts");
        triggers.extend([
            ("taskrun_terminal_settlement_immutable", "CREATE TRIGGER taskrun_terminal_settlement_immutable BEFORE UPDATE ON taskrun_terminal_settlement_receipts BEGIN SELECT RAISE(ABORT,'TaskRun terminal settlement is append only'); END"),
            ("taskrun_terminal_settlement_no_delete", "CREATE TRIGGER taskrun_terminal_settlement_no_delete BEFORE DELETE ON taskrun_terminal_settlement_receipts BEGIN SELECT RAISE(ABORT,'TaskRun terminal settlement is append only'); END"),
            ("schema_v12_fence_taskrun_terminal_settlement_receipts_insert", "CREATE TRIGGER \"schema_v12_fence_taskrun_terminal_settlement_receipts_insert\" AFTER INSERT ON \"taskrun_terminal_settlement_receipts\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"),
            ("schema_v12_fence_taskrun_terminal_settlement_receipts_update", "CREATE TRIGGER \"schema_v12_fence_taskrun_terminal_settlement_receipts_update\" AFTER UPDATE ON \"taskrun_terminal_settlement_receipts\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"),
            ("schema_v12_fence_taskrun_terminal_settlement_receipts_delete", "CREATE TRIGGER \"schema_v12_fence_taskrun_terminal_settlement_receipts_delete\" AFTER DELETE ON \"taskrun_terminal_settlement_receipts\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"),
        ]);
    }
    if marker.0 >= 50 {
        tables.push("provider_terminal_dispositions");
        triggers.extend([
            ("provider_terminal_dispositions_immutable", "CREATE TRIGGER provider_terminal_dispositions_immutable BEFORE UPDATE ON provider_terminal_dispositions BEGIN SELECT RAISE(ABORT,'Provider terminal disposition is append only'); END"),
            ("provider_terminal_dispositions_no_delete", "CREATE TRIGGER provider_terminal_dispositions_no_delete BEFORE DELETE ON provider_terminal_dispositions BEGIN SELECT RAISE(ABORT,'Provider terminal disposition is append only'); END"),
            ("schema_v12_fence_provider_terminal_dispositions_insert", "CREATE TRIGGER \"schema_v12_fence_provider_terminal_dispositions_insert\" AFTER INSERT ON \"provider_terminal_dispositions\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"),
            ("schema_v12_fence_provider_terminal_dispositions_update", "CREATE TRIGGER \"schema_v12_fence_provider_terminal_dispositions_update\" AFTER UPDATE ON \"provider_terminal_dispositions\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"),
            ("schema_v12_fence_provider_terminal_dispositions_delete", "CREATE TRIGGER \"schema_v12_fence_provider_terminal_dispositions_delete\" AFTER DELETE ON \"provider_terminal_dispositions\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"),
        ]);
    }
    add_v51_local_schema_extensions(marker.0, &mut tables, &mut indexes, &mut triggers);
    if marker.0 >= 52 {
        v52_add_credential_schema_extensions(&mut tables, &mut indexes, &mut triggers);
    }
    if marker.0 >= 53 {
        v53_add_schema_extensions(&mut tables, &mut triggers);
    }
    if marker.0 >= 54 {
        v54_add_schema_extensions(&mut tables, &mut triggers);
    }
    if marker.0 >= 55 {
        v55_add_schema_extensions(&mut tables, &mut triggers);
    }
    if marker.0 >= 56 {
        v56_add_schema_extensions(&mut tables, &mut triggers);
    }
    if marker.0 >= 57 {
        v57_add_schema_extensions(&mut tables, &mut triggers);
    }
    if marker.0 >= 58 {
        v58_add_schema_extensions(&mut tables, &mut indexes, &mut triggers);
    }
    if marker.0 >= 59 {
        v59_add_schema_extensions(&mut tables, &mut indexes, &mut triggers);
    }
    if marker.0 >= 60 {
        v60_add_schema_extensions(&mut tables, &mut triggers);
    }
    if marker.0 >= 61 {
        v61_add_schema_extensions(&mut tables, &mut triggers);
    }
    if marker.0 >= 62 {
        v62_add_schema_extensions(&mut tables, &mut triggers);
    }
    if marker.0 >= 63 {
        v63_add_schema_extensions(&mut tables, &mut triggers);
    }
    if marker.0 >= 64 {
        v64_add_schema_extensions(&mut tables, &mut indexes, &mut triggers);
    }
    if marker.0 >= 68 {
        v68_add_schema_extensions(&mut tables, &mut indexes, &mut triggers);
    } else if marker.0 >= 67 {
        v67_add_schema_extensions(&mut tables, &mut indexes, &mut triggers);
    } else if marker.0 >= 66 {
        v66_add_schema_extensions(&mut tables, &mut indexes, &mut triggers);
    } else if marker.0 >= 65 {
        v65_add_schema_extensions(&mut tables, &mut indexes, &mut triggers);
    }
    if marker.0 >= 47 {
        tables.push("text_only_taskrun_lineage");
        triggers.extend([
            ("text_only_taskrun_lineage_immutable", "CREATE TRIGGER text_only_taskrun_lineage_immutable BEFORE UPDATE ON text_only_taskrun_lineage BEGIN SELECT RAISE(ABORT,'TextOnly TaskRun lineage is append only'); END"),
            ("text_only_taskrun_lineage_no_delete", "CREATE TRIGGER text_only_taskrun_lineage_no_delete BEFORE DELETE ON text_only_taskrun_lineage BEGIN SELECT RAISE(ABORT,'TextOnly TaskRun lineage is append only'); END"),
            ("text_only_taskrun_lineage_no_workspace_collision", "CREATE TRIGGER text_only_taskrun_lineage_no_workspace_collision BEFORE INSERT ON text_only_taskrun_lineage WHEN EXISTS(SELECT 1 FROM task_run_workspace_lineage WHERE taskrun_id=NEW.taskrun_id) BEGIN SELECT RAISE(ABORT,'TaskRun lineage owner collision'); END"),
            ("schema_v12_fence_text_only_taskrun_lineage_insert", "CREATE TRIGGER \"schema_v12_fence_text_only_taskrun_lineage_insert\" AFTER INSERT ON \"text_only_taskrun_lineage\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"),
            ("schema_v12_fence_text_only_taskrun_lineage_update", "CREATE TRIGGER \"schema_v12_fence_text_only_taskrun_lineage_update\" AFTER UPDATE ON \"text_only_taskrun_lineage\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"),
            ("schema_v12_fence_text_only_taskrun_lineage_delete", "CREATE TRIGGER \"schema_v12_fence_text_only_taskrun_lineage_delete\" AFTER DELETE ON \"text_only_taskrun_lineage\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"),
        ]);
    }
    let extensions = CredentialSchemaExtensions {
        tables: &tables,
        indexes: &indexes,
        triggers: &triggers,
        replacements: &[],
    };
    let checks = [
        ("catalog-marker", catalog_marker_matches(connection)?),
        (
            "credential-guards",
            inherited_credential_guards_match(connection)?,
        ),
        ("v37", v37_structure_matches(connection)?),
        (
            "v29-catalog",
            v29_catalog_matches_with_extensions(
                connection,
                v35_operation_index_names(),
                &extensions,
            )?,
        ),
        (
            "v36-receipt",
            project_workspace_schema::v36_receipt_table_matches(connection)?,
        ),
        (
            "global-workspace",
            project_workspace_schema::validation::global_command_triggers_match(connection)?,
        ),
        ("v39-lineage", v39_lineage_table_matches(connection)?),
        ("v40-scope", v40_scope_table_matches(connection)?),
        ("v41-node", execution_node_table_matches(connection)?),
        ("v42-claim", claim_tables_match(connection)?),
        (
            "v42-immutability",
            claim_immutability_triggers_match(connection)?,
        ),
        (
            "v42-global",
            claim_global_command_triggers_match(connection)?,
        ),
        ("v42-fence", claim_fence_triggers_match(connection)?),
    ];
    Ok(checks.iter().all(|(_, matches)| *matches))
}

include!("v42_taskrun_claim_checks.rs");
