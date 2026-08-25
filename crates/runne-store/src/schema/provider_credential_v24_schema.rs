const V24_TRIGGERS: [(&str, &str); 19] = [
    (
        "provider_credential_operation_insert_prepared",
        "CREATE TRIGGER provider_credential_operation_insert_prepared BEFORE INSERT ON provider_credential_operations WHEN NEW.state != 'PREPARED' OR NEW.continuation_binding_digest IS NOT NULL OR NEW.process_release_binding_digest IS NOT NULL OR NEW.native_effect_disposition IS NOT NULL OR NEW.readback_observation_digest IS NOT NULL OR NEW.terminal_disposition IS NOT NULL OR NEW.tombstone_digest IS NOT NULL OR NOT EXISTS(SELECT 1 FROM provider_credential_authority_heads WHERE provider_id = NEW.provider_id AND lifecycle_revision = NEW.expected_lifecycle_revision AND credential_fence = NEW.expected_credential_fence AND hard_fence_disposition IS NULL AND release_migration_state IN ('NONE', 'CLEARED') AND (NEW.allocated_credential_version IS NULL OR next_credential_version = NEW.allocated_credential_version)) BEGIN SELECT RAISE(ABORT, 'credential operation requires the current unfenced authority head and exact allocation'); END",
    ),
    (
        "provider_credential_operation_allocate_version",
        "CREATE TRIGGER provider_credential_operation_allocate_version AFTER INSERT ON provider_credential_operations WHEN NEW.allocated_credential_version IS NOT NULL BEGIN UPDATE provider_credential_authority_heads SET next_credential_version = next_credential_version + 1 WHERE provider_id = NEW.provider_id AND lifecycle_revision = NEW.expected_lifecycle_revision AND credential_fence = NEW.expected_credential_fence AND hard_fence_disposition IS NULL AND release_migration_state IN ('NONE', 'CLEARED') AND next_credential_version = NEW.allocated_credential_version; END",
    ),
    (
        "provider_credential_operation_transition",
        "CREATE TRIGGER provider_credential_operation_transition BEFORE UPDATE ON provider_credential_operations WHEN NEW.operation_id != OLD.operation_id OR NEW.provider_id != OLD.provider_id OR NEW.action != OLD.action OR NEW.command_id != OLD.command_id OR NEW.idempotency_key != OLD.idempotency_key OR NEW.expected_lifecycle_revision != OLD.expected_lifecycle_revision OR NEW.expected_credential_fence != OLD.expected_credential_fence OR NEW.allocated_credential_version IS NOT OLD.allocated_credential_version OR NEW.allocated_ref_digest IS NOT OLD.allocated_ref_digest OR NEW.begin_proof_digest != OLD.begin_proof_digest OR NEW.created_at != OLD.created_at OR NEW.migration_id IS NOT OLD.migration_id OR NEW.migration_phase IS NOT OLD.migration_phase OR NEW.migration_old_tuple_digest IS NOT OLD.migration_old_tuple_digest OR NEW.migration_new_tuple_digest IS NOT OLD.migration_new_tuple_digest OR (OLD.continuation_binding_digest IS NOT NULL AND NEW.continuation_binding_digest IS NOT OLD.continuation_binding_digest) OR (OLD.process_release_binding_digest IS NOT NULL AND NEW.process_release_binding_digest IS NOT OLD.process_release_binding_digest) OR (OLD.native_effect_disposition IS NOT NULL AND NEW.native_effect_disposition IS NOT OLD.native_effect_disposition) OR (OLD.readback_observation_digest IS NOT NULL AND NEW.readback_observation_digest IS NOT OLD.readback_observation_digest) OR (OLD.terminal_disposition IS NOT NULL AND NEW.terminal_disposition IS NOT OLD.terminal_disposition) OR (OLD.tombstone_digest IS NOT NULL AND NEW.tombstone_digest IS NOT OLD.tombstone_digest) OR (OLD.continuation_binding_digest IS NULL AND NEW.continuation_binding_digest IS NOT NULL AND NOT (OLD.state = 'PREPARED' AND NEW.state = 'CLAIMED')) OR (OLD.process_release_binding_digest IS NULL AND NEW.process_release_binding_digest IS NOT NULL AND NOT (OLD.state = 'PREPARED' AND NEW.state = 'CLAIMED')) OR (OLD.native_effect_disposition IS NULL AND NEW.native_effect_disposition IS NOT NULL AND NOT (OLD.state = 'CLAIMED' AND NEW.state = 'NATIVE_EFFECT_OBSERVED')) OR (OLD.readback_observation_digest IS NULL AND NEW.readback_observation_digest IS NOT NULL AND NOT ((OLD.state = 'NATIVE_EFFECT_OBSERVED' AND NEW.state IN ('READBACK_VERIFIED', 'FAILED')) OR (OLD.state = 'CLAIMED' AND NEW.state = 'FAILED'))) OR (OLD.terminal_disposition IS NULL AND NEW.terminal_disposition IS NOT NULL AND NOT (NEW.state IN ('COMPLETED', 'FAILED', 'EXPIRED', 'CANCELLED') AND NEW.state != OLD.state)) OR (OLD.tombstone_digest IS NULL AND NEW.tombstone_digest IS NOT NULL AND NOT (OLD.state IN ('COMPLETED', 'FAILED', 'EXPIRED', 'CANCELLED') AND NEW.state = 'TOMBSTONED')) OR (NEW.state = 'PREPARED' AND (NEW.continuation_binding_digest IS NOT NULL OR NEW.process_release_binding_digest IS NOT NULL OR NEW.native_effect_disposition IS NOT NULL OR NEW.readback_observation_digest IS NOT NULL OR NEW.terminal_disposition IS NOT NULL OR NEW.tombstone_digest IS NOT NULL)) OR (NEW.state = 'CLAIMED' AND (NEW.native_effect_disposition IS NOT NULL OR NEW.readback_observation_digest IS NOT NULL OR NEW.terminal_disposition IS NOT NULL OR NEW.tombstone_digest IS NOT NULL)) OR (NEW.state = 'NATIVE_EFFECT_OBSERVED' AND (NEW.readback_observation_digest IS NOT NULL OR NEW.terminal_disposition IS NOT NULL OR NEW.tombstone_digest IS NOT NULL)) OR (NEW.state = 'READBACK_VERIFIED' AND NEW.tombstone_digest IS NOT NULL) OR (OLD.state = 'PREPARED' AND NEW.state = 'CLAIMED' AND (NEW.continuation_binding_digest IS NULL OR NEW.process_release_binding_digest IS NULL)) OR (OLD.state = 'CLAIMED' AND NEW.state = 'NATIVE_EFFECT_OBSERVED' AND NEW.native_effect_disposition IS NULL) OR (OLD.state = 'NATIVE_EFFECT_OBSERVED' AND NEW.state = 'READBACK_VERIFIED' AND NEW.readback_observation_digest IS NULL) OR (OLD.state IN ('CLAIMED', 'NATIVE_EFFECT_OBSERVED') AND NEW.state = 'FAILED' AND NEW.readback_observation_digest IS NULL) OR (NEW.state IN ('COMPLETED', 'FAILED', 'EXPIRED', 'CANCELLED') AND NEW.state != OLD.state AND NEW.terminal_disposition IS NULL) OR NEW.updated_at < OLD.updated_at OR OLD.state = 'TOMBSTONED' OR NOT (NEW.state = OLD.state OR (OLD.state = 'PREPARED' AND NEW.state IN ('CLAIMED', 'FAILED', 'EXPIRED', 'CANCELLED')) OR (OLD.state = 'CLAIMED' AND NEW.state IN ('NATIVE_EFFECT_OBSERVED', 'FAILED')) OR (OLD.state = 'NATIVE_EFFECT_OBSERVED' AND NEW.state IN ('READBACK_VERIFIED', 'FAILED')) OR (OLD.state = 'READBACK_VERIFIED' AND NEW.state = 'COMPLETED') OR (OLD.state IN ('COMPLETED', 'FAILED', 'EXPIRED', 'CANCELLED') AND NEW.state = 'TOMBSTONED')) BEGIN SELECT RAISE(ABORT, 'invalid credential operation transition or evidence ownership'); END",
    ),
    (
        "provider_credential_operation_permanent",
        "CREATE TRIGGER provider_credential_operation_permanent BEFORE DELETE ON provider_credential_operations BEGIN SELECT RAISE(ABORT, 'credential operation is permanent'); END",
    ),
    (
        "provider_credential_ticket_insert_issued",
        "CREATE TRIGGER provider_credential_ticket_insert_issued BEFORE INSERT ON provider_credential_ticket_attempts WHEN NEW.state != 'ISSUED' OR NEW.attempt != COALESCE((SELECT MAX(attempt) + 1 FROM provider_credential_ticket_attempts WHERE operation_id = NEW.operation_id), 1) OR EXISTS(SELECT 1 FROM provider_credential_ticket_attempts WHERE operation_id = NEW.operation_id AND state != 'TOMBSTONED') BEGIN SELECT RAISE(ABORT, 'credential ticket must begin at the strict next attempt after prior tombstones'); END",
    ),
    (
        "provider_credential_ticket_transition",
        "CREATE TRIGGER provider_credential_ticket_transition BEFORE UPDATE ON provider_credential_ticket_attempts WHEN NEW.operation_id != OLD.operation_id OR NEW.attempt != OLD.attempt OR NEW.ticket_digest != OLD.ticket_digest OR NEW.continuation_binding_digest != OLD.continuation_binding_digest OR NEW.issued_at != OLD.issued_at OR NEW.expires_at != OLD.expires_at OR OLD.state = 'TOMBSTONED' OR NOT (NEW.state = OLD.state OR (OLD.state = 'ISSUED' AND NEW.state IN ('CLAIMED', 'EXPIRED')) OR (OLD.state IN ('CLAIMED', 'EXPIRED') AND NEW.state = 'TOMBSTONED')) BEGIN SELECT RAISE(ABORT, 'invalid credential ticket transition'); END",
    ),
    (
        "provider_credential_ticket_permanent",
        "CREATE TRIGGER provider_credential_ticket_permanent BEFORE DELETE ON provider_credential_ticket_attempts BEGIN SELECT RAISE(ABORT, 'credential ticket is permanent'); END",
    ),
    (
        "provider_credential_head_monotonic",
        "CREATE TRIGGER provider_credential_head_monotonic BEFORE UPDATE ON provider_credential_authority_heads WHEN NEW.provider_id != OLD.provider_id OR NEW.lifecycle_revision < OLD.lifecycle_revision OR NEW.credential_fence < OLD.credential_fence OR NEW.readiness_revision < OLD.readiness_revision OR NEW.next_credential_version < OLD.next_credential_version OR NEW.observed_at_high_water < OLD.observed_at_high_water OR NEW.pre_v24_quarantine_digest IS NOT OLD.pre_v24_quarantine_digest OR NEW.pre_v24_quarantine_count != OLD.pre_v24_quarantine_count OR NEW.legacy_import_consumed < OLD.legacy_import_consumed OR (OLD.legacy_import_consumed = 1 AND (NEW.legacy_source_binding_digest IS NOT OLD.legacy_source_binding_digest OR NEW.legacy_consumed_lifecycle_revision IS NOT OLD.legacy_consumed_lifecycle_revision OR NEW.legacy_cleanup_operation_id IS NOT OLD.legacy_cleanup_operation_id)) OR (OLD.hard_fence_disposition IS NOT NULL AND (NEW.hard_fence_disposition IS NULL OR NEW.hard_fence_diagnostic_digest IS NOT OLD.hard_fence_diagnostic_digest OR NEW.active_credential_version IS NOT NULL OR NEW.active_ref_digest IS NOT NULL)) OR (OLD.hard_fence_disposition IS NULL AND NEW.hard_fence_disposition IS NOT NULL AND (NEW.lifecycle_revision <= OLD.lifecycle_revision OR NEW.credential_fence <= OLD.credential_fence OR NEW.readiness_revision <= OLD.readiness_revision OR NEW.active_credential_version IS NOT NULL)) BEGIN SELECT RAISE(ABORT, 'credential authority head is monotonic'); END",
    ),
    (
        "provider_credential_head_active_lifecycle",
        "CREATE TRIGGER provider_credential_head_active_lifecycle BEFORE UPDATE ON provider_credential_authority_heads WHEN (NEW.active_credential_version IS NOT OLD.active_credential_version OR NEW.active_ref_digest IS NOT OLD.active_ref_digest) AND NOT (NEW.lifecycle_revision > OLD.lifecycle_revision AND NEW.credential_fence > OLD.credential_fence AND NEW.readiness_revision > OLD.readiness_revision AND ((NEW.active_credential_version IS NOT NULL AND EXISTS(SELECT 1 FROM provider_credential_operations AS o WHERE o.provider_id = NEW.provider_id AND o.expected_lifecycle_revision = OLD.lifecycle_revision AND o.expected_credential_fence = OLD.credential_fence AND o.allocated_credential_version = NEW.active_credential_version AND o.allocated_ref_digest = NEW.active_ref_digest AND ((o.action = 'PAIR' AND o.state = 'READBACK_VERIFIED') OR (o.action = 'MIGRATE_LEGACY' AND OLD.legacy_import_consumed = 0 AND NEW.legacy_import_consumed = 1 AND o.state = 'COMPLETED')))) OR (NEW.active_credential_version IS NULL AND (NEW.hard_fence_disposition IS NOT NULL OR EXISTS(SELECT 1 FROM provider_credential_operations AS o WHERE o.provider_id = NEW.provider_id AND o.action = 'REVOKE' AND o.expected_lifecycle_revision = OLD.lifecycle_revision AND o.expected_credential_fence = OLD.credential_fence AND o.state IN ('PREPARED', 'CLAIMED', 'NATIVE_EFFECT_OBSERVED', 'READBACK_VERIFIED', 'COMPLETED')))))) BEGIN SELECT RAISE(ABORT, 'active credential mutation requires fenced revision and owned operation'); END",
    ),
    (
        "provider_credential_head_legacy_barrier",
        "CREATE TRIGGER provider_credential_head_legacy_barrier BEFORE UPDATE ON provider_credential_authority_heads WHEN OLD.legacy_import_consumed = 0 AND NEW.legacy_import_consumed = 1 AND (OLD.active_credential_version IS NOT NULL OR OLD.active_ref_digest IS NOT NULL OR NEW.active_credential_version IS NULL OR NEW.active_ref_digest IS NULL OR NEW.lifecycle_revision <= OLD.lifecycle_revision OR NEW.credential_fence <= OLD.credential_fence OR NEW.readiness_revision <= OLD.readiness_revision OR NEW.legacy_consumed_lifecycle_revision != NEW.lifecycle_revision OR NOT EXISTS(SELECT 1 FROM provider_credential_operations WHERE operation_id = NEW.legacy_cleanup_operation_id AND provider_id = NEW.provider_id AND action = 'LEGACY_SOURCE_CLEANUP' AND state IN ('PREPARED', 'CLAIMED', 'NATIVE_EFFECT_OBSERVED', 'READBACK_VERIFIED'))) BEGIN SELECT RAISE(ABORT, 'legacy consumed barrier requires a fresh active cutover and linked cleanup'); END",
    ),
    (
        "provider_credential_head_insert_unconsumed",
        "CREATE TRIGGER provider_credential_head_insert_unconsumed BEFORE INSERT ON provider_credential_authority_heads WHEN NEW.lifecycle_revision != 1 OR NEW.credential_fence != 1 OR NEW.readiness_revision != 1 OR NEW.next_credential_version != 1 OR NEW.active_credential_version IS NOT NULL OR NEW.active_ref_digest IS NOT NULL OR NEW.hard_fence_disposition IS NOT NULL OR NEW.hard_fence_diagnostic_digest IS NOT NULL OR NEW.observed_at_high_water != 0 OR NEW.pre_v24_quarantine_count != 0 OR NEW.pre_v24_quarantine_digest != X'0000000000000000000000000000000000000000000000000000000000000000' OR NEW.legacy_import_consumed != 0 OR NEW.legacy_source_binding_digest IS NOT NULL OR NEW.legacy_consumed_lifecycle_revision IS NOT NULL OR NEW.legacy_cleanup_operation_id IS NOT NULL OR NEW.release_migration_state != 'NONE' OR NEW.release_migration_fence != 0 OR NEW.release_migration_binding_digest IS NOT NULL OR NEW.release_migration_operation_id IS NOT NULL BEGIN SELECT RAISE(ABORT, 'credential authority head must begin with default inactive unfenced barriers'); END",
    ),
    (
        "provider_credential_head_release_migration",
        "CREATE TRIGGER provider_credential_head_release_migration BEFORE UPDATE ON provider_credential_authority_heads WHEN NEW.release_migration_fence < OLD.release_migration_fence OR ((NEW.release_migration_state != OLD.release_migration_state OR NEW.release_migration_binding_digest IS NOT OLD.release_migration_binding_digest OR NEW.release_migration_operation_id IS NOT OLD.release_migration_operation_id) AND NEW.readiness_revision <= OLD.readiness_revision) OR (OLD.release_migration_state IN ('NONE', 'CLEARED') AND NEW.release_migration_state = 'PENDING' AND NEW.credential_fence <= OLD.credential_fence) OR NOT ((NEW.release_migration_state = OLD.release_migration_state AND NEW.release_migration_fence = OLD.release_migration_fence AND NEW.release_migration_binding_digest IS OLD.release_migration_binding_digest AND NEW.release_migration_operation_id IS OLD.release_migration_operation_id) OR (OLD.release_migration_state IN ('NONE', 'CLEARED') AND NEW.release_migration_state = 'PENDING' AND NEW.release_migration_fence > OLD.release_migration_fence) OR (OLD.release_migration_state = 'PENDING' AND NEW.release_migration_state = 'VERIFIED' AND NEW.release_migration_fence = OLD.release_migration_fence AND NEW.release_migration_binding_digest = OLD.release_migration_binding_digest AND NEW.release_migration_operation_id = OLD.release_migration_operation_id) OR (OLD.release_migration_state = 'VERIFIED' AND NEW.release_migration_state = 'CLEARED' AND NEW.release_migration_fence = OLD.release_migration_fence AND NEW.release_migration_binding_digest = OLD.release_migration_binding_digest AND NEW.release_migration_operation_id = OLD.release_migration_operation_id)) OR (NEW.release_migration_state != 'NONE' AND NOT EXISTS(SELECT 1 FROM provider_credential_operations WHERE operation_id = NEW.release_migration_operation_id AND provider_id = NEW.provider_id AND action = 'WRITER_IDENTITY_MIGRATION_VERIFY' AND migration_phase = 'VERIFY' AND migration_new_tuple_digest = NEW.release_migration_binding_digest AND (NEW.release_migration_state = 'PENDING' OR state = 'COMPLETED'))) BEGIN SELECT RAISE(ABORT, 'invalid credential release migration transition'); END",
    ),
    (
        "provider_credential_head_permanent",
        "CREATE TRIGGER provider_credential_head_permanent BEFORE DELETE ON provider_credential_authority_heads BEGIN SELECT RAISE(ABORT, 'credential authority head is permanent'); END",
    ),
    (
        "provider_credential_readiness_append_only",
        "CREATE TRIGGER provider_credential_readiness_append_only BEFORE UPDATE ON provider_credential_readiness_observations BEGIN SELECT RAISE(ABORT, 'credential readiness observation is append-only'); END",
    ),
    (
        "provider_credential_readiness_insert_current",
        "CREATE TRIGGER provider_credential_readiness_insert_current BEFORE INSERT ON provider_credential_readiness_observations WHEN NOT EXISTS(SELECT 1 FROM provider_credential_authority_heads AS h WHERE h.provider_id = NEW.provider_id AND h.lifecycle_revision = NEW.lifecycle_revision AND h.readiness_revision = NEW.readiness_revision AND ((NEW.disposition = 'READY' AND h.hard_fence_disposition IS NULL AND h.release_migration_state IN ('NONE', 'CLEARED') AND h.active_credential_version IS NOT NULL AND NEW.active_binding_digest = h.active_ref_digest) OR (NEW.disposition != 'READY' AND (h.hard_fence_disposition IS NULL OR NEW.disposition = 'INVARIANT_FAILURE') AND (h.hard_fence_disposition IS NULL OR NEW.active_binding_digest IS NULL) AND (h.release_migration_state IN ('NONE', 'CLEARED') OR NEW.disposition != 'READY'))) AND (NEW.operation_id IS NULL OR EXISTS(SELECT 1 FROM provider_credential_operations AS o WHERE o.operation_id = NEW.operation_id AND o.provider_id = NEW.provider_id AND o.state NOT IN ('TOMBSTONED', 'CANCELLED', 'EXPIRED')))) BEGIN SELECT RAISE(ABORT, 'credential readiness observation is stale, fenced, or unowned'); END",
    ),
    (
        "provider_credential_readiness_permanent",
        "CREATE TRIGGER provider_credential_readiness_permanent BEFORE DELETE ON provider_credential_readiness_observations BEGIN SELECT RAISE(ABORT, 'credential readiness observation is permanent'); END",
    ),
    (
        "provider_credential_verification_append_only",
        "CREATE TRIGGER provider_credential_verification_append_only BEFORE UPDATE ON provider_credential_verification_observations WHEN NEW.observation_id != OLD.observation_id OR NEW.provider_id != OLD.provider_id OR NEW.verification_kind != OLD.verification_kind OR NEW.lifecycle_revision != OLD.lifecycle_revision OR NEW.credential_fence != OLD.credential_fence OR NEW.intent_proof_digest != OLD.intent_proof_digest OR NEW.proof_consumed != OLD.proof_consumed OR NEW.verifier_revision != OLD.verifier_revision OR NEW.started_at != OLD.started_at OR NEW.expires_at_high_water != OLD.expires_at_high_water OR NEW.operation_id IS NOT OLD.operation_id OR OLD.state = 'COMPLETED' OR NEW.state != 'COMPLETED' OR OLD.state != 'LEASED' OR NEW.result IS NULL OR NEW.observed_at IS NULL OR NEW.observed_at >= NEW.expires_at_high_water OR NOT EXISTS(SELECT 1 FROM provider_credential_authority_heads AS h WHERE h.provider_id = NEW.provider_id AND h.lifecycle_revision = NEW.lifecycle_revision AND h.credential_fence = NEW.credential_fence AND h.observed_at_high_water = NEW.observed_at AND h.hard_fence_disposition IS NULL AND h.release_migration_state IN ('NONE', 'CLEARED')) BEGIN SELECT RAISE(ABORT, 'credential verification lease completion is stale, immutable, or expired'); END",
    ),
    (
        "provider_credential_verification_insert_current",
        "CREATE TRIGGER provider_credential_verification_insert_current BEFORE INSERT ON provider_credential_verification_observations WHEN NEW.state != 'LEASED' OR NEW.result IS NOT NULL OR NEW.observed_at IS NOT NULL OR NEW.proof_consumed != 1 OR NOT EXISTS(SELECT 1 FROM provider_credential_authority_heads AS h WHERE h.provider_id = NEW.provider_id AND h.lifecycle_revision = NEW.lifecycle_revision AND h.credential_fence = NEW.credential_fence AND h.observed_at_high_water = NEW.started_at AND h.hard_fence_disposition IS NULL AND h.release_migration_state IN ('NONE', 'CLEARED') AND (NEW.operation_id IS NULL OR EXISTS(SELECT 1 FROM provider_credential_operations AS o WHERE o.operation_id = NEW.operation_id AND o.provider_id = NEW.provider_id AND o.state NOT IN ('TOMBSTONED', 'CANCELLED', 'EXPIRED'))) AND (NEW.verification_kind != 'REMOTE' OR EXISTS(SELECT 1 FROM provider_credential_verification_observations AS local WHERE local.provider_id = NEW.provider_id AND local.verification_kind = 'LOCAL' AND local.lifecycle_revision = NEW.lifecycle_revision AND local.credential_fence = NEW.credential_fence AND local.verifier_revision = NEW.verifier_revision AND local.state = 'COMPLETED' AND local.result = 'VERIFIED' AND local.observed_at <= NEW.started_at))) BEGIN SELECT RAISE(ABORT, 'credential verification lease is stale, fenced, unconsumed, or premature'); END",
    ),
    (
        "provider_credential_verification_permanent",
        "CREATE TRIGGER provider_credential_verification_permanent BEFORE DELETE ON provider_credential_verification_observations BEGIN SELECT RAISE(ABORT, 'credential verification observation is permanent'); END",
    ),
];

pub(super) fn install_v24_triggers(transaction: &Transaction<'_>) -> SqliteResult<()> {
    for (_, trigger) in V24_TRIGGERS {
        transaction.execute_batch(trigger)?;
    }
    Ok(())
}

pub(super) fn v24_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 24 || !v24_predecessor_matches(connection)? || !v24_catalog_matches(connection)? {
        return Ok(false);
    }
    for table in [
        "provider_credential_operations",
        "provider_credential_ticket_attempts",
        "provider_credential_authority_heads",
        "provider_credential_readiness_observations",
        "provider_credential_verification_observations",
    ] {
        if !v24_table_sql_matches_migration(connection, table)? {
            return Ok(false);
        }
    }
    for (name, expected) in V24_TRIGGERS {
        if !v24_trigger_matches(connection, name, expected)? {
            return Ok(false);
        }
    }
    v24_index_matches(connection, "provider_credential_one_non_terminal_operation")
}

fn v24_predecessor_matches(connection: &Connection) -> SqliteResult<bool> {
    let mut additional = vec![
        "aggregate_state_snapshots_bind_insert",
        "aggregate_state_snapshots_bind_update",
    ];
    additional.extend(V24_TRIGGERS.iter().map(|(name, _)| *name));
    let v18 = project_workspace_schema::v18_base_matches_with_additional_triggers(
        connection,
        &additional,
    )?;
    let v20 = table_sql_matches_migration(
        connection,
        "aggregate_state_snapshots",
        replay_promotion_snapshot_schema::MIGRATION_V20,
    )? && index_matches(
        connection,
        "idx_aggregate_state_snapshots_head_position",
        "aggregate_state_snapshots",
        &["head_global_position"],
    )? && snapshot_triggers_match(connection)?;
    let strict_v9 = is_released_strict_v9_with_v12_fence(connection)?;
    let v12 = provider_v12_core_matches(connection)?;
    let v13 = v13_unchanged_tables_match(connection)?;
    let v14 = provider_schema::v14_base_matches(connection, v12, v13)?;
    let provider_chain = v14 && provider_schema::v15_base_matches(connection, v14)?;
    let intent_digest = connection
        .prepare("PRAGMA table_info(process_registry)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<SqliteResult<Vec<_>>>()?
        .iter()
        .any(|name| name == "intent_digest");
    Ok(v18
        && v20
        && strict_v9
        && provider_chain
        && intent_digest
        && table_sql_matches_migration(connection, "approvals", MIGRATION_V23)?
        && index_matches(
            connection,
            "idx_approvals_pending",
            "approvals",
            &["principal_id", "state", "expires_at", "approval_id"],
        )?)
}

fn snapshot_triggers_match(connection: &Connection) -> SqliteResult<bool> {
    [
        (
            "aggregate_state_snapshots_bind_insert",
            replay_snapshot_schema::SNAPSHOT_INSERT_TRIGGER,
        ),
        (
            "aggregate_state_snapshots_bind_update",
            replay_snapshot_schema::SNAPSHOT_UPDATE_TRIGGER,
        ),
    ]
    .into_iter()
    .try_fold(true, |valid, (name, expected)| {
        Ok(valid && v24_trigger_matches(connection, name, expected)?)
    })
}

fn v24_catalog_matches(connection: &Connection) -> SqliteResult<bool> {
    let mut tables = RELEASED_V13_TABLES.to_vec();
    tables.extend([
        "provider_effect_starts",
        "provider_credential_versions",
        "provider_credential_clock_high_water",
        "provider_credential_provisions",
        "provider_credential_effect_bindings",
        "bootstrap_reservations",
        "bootstrap_reservation_tombstones",
        "bootstrap_last_observed_clock",
        "projects",
        "workspaces",
        "root_admission_nonces",
        "project_workspace_command_receipts",
        "workspace_identity_history",
        "task_run_workspace_lineage",
        "aggregate_state_snapshots",
        "process_registry",
        "process_output",
        "approvals",
        "provider_credential_operations",
        "provider_credential_ticket_attempts",
        "provider_credential_authority_heads",
        "provider_credential_readiness_observations",
        "provider_credential_verification_observations",
    ]);
    let mut indexes = RELEASED_V12_EXPLICIT_INDEXES.to_vec();
    indexes.extend([
        "provider_credential_one_active",
        "provider_credential_one_pending_provision",
        "bootstrap_reservation_unexpired",
        "idx_aggregate_state_snapshots_head_position",
        "idx_process_registry_owner",
        "idx_approvals_pending",
        "provider_credential_one_non_terminal_operation",
    ]);
    released_catalog_matches_with_indexes(connection, &tables, &indexes)
}

fn v24_index_matches(connection: &Connection, name: &str) -> SqliteResult<bool> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?1",
            [name],
            |row| row.get(0),
        )
        .optional()?;
    let expected = MIGRATION_V24
        .split(';')
        .map(str::trim)
        .find(|sql| sql.starts_with(&format!("CREATE UNIQUE INDEX {name}")));
    Ok(actual.is_some_and(|actual| {
        expected.is_some_and(|expected| normalize_v24_ddl(&actual) == normalize_v24_ddl(expected))
    }))
}

fn v24_table_sql_matches_migration(connection: &Connection, table: &str) -> SqliteResult<bool> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get(0),
        )
        .optional()?;
    let expected = MIGRATION_V24
        .split(';')
        .map(str::trim)
        .find(|sql| sql.starts_with(&format!("CREATE TABLE {table} ")));
    Ok(actual.is_some_and(|actual| {
        expected.is_some_and(|expected| normalize_v24_ddl(&actual) == normalize_v24_ddl(expected))
    }))
}

fn normalize_v24_ddl(ddl: &str) -> String {
    let mut normalized = String::with_capacity(ddl.len());
    let mut chars = ddl.chars().peekable();
    let mut quote = None;
    while let Some(ch) = chars.next() {
        if let Some(delimiter) = quote {
            normalized.push(ch);
            if ch == delimiter {
                if chars.peek() == Some(&delimiter) {
                    normalized.push(chars.next().unwrap());
                } else {
                    quote = None;
                }
            }
            continue;
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
            normalized.push(ch);
        } else if ch == '-' && chars.peek() == Some(&'-') {
            chars.next();
            while chars.next().is_some_and(|next| next != '\n') {}
        } else if ch == '/' && chars.peek() == Some(&'*') {
            chars.next();
            while let Some(next) = chars.next() {
                if next == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    break;
                }
            }
        } else if !ch.is_whitespace() {
            normalized.extend(ch.to_lowercase());
        }
    }
    normalized
}

fn v24_trigger_matches(connection: &Connection, name: &str, expected: &str) -> SqliteResult<bool> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ?1",
            [name],
            |row| row.get(0),
        )
        .optional()?;
    Ok(actual.is_some_and(|actual| {
        normalize_sql(&actual) == normalize_sql(expected.trim().trim_end_matches(';'))
    }))
}
