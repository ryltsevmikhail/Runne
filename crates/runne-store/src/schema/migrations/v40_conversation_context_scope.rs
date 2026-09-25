// ── Migration V40: durable conversation context scope ─────────────────────
//
// NM-06 provenance: every Conversation carries an explicit, durable delivery
// context recorded in the SAME transaction as ConversationCreated. The
// marker — not the absence of records — is what the delivery trust gate
// reasons over, so pre-V40 conversations stay unclassified (fail-closed) and
// rows are never backfilled with an assumed scope.

pub(super) const MIGRATION_V40: &str = r#"
CREATE TABLE conversation_context_scope (
    conversation_id BLOB PRIMARY KEY CHECK(length(conversation_id) = 16),
    context_scope TEXT NOT NULL CHECK(context_scope IN ('workspace', 'text_only')),
    recorded_at INTEGER NOT NULL
);
"#;

pub(super) fn apply_v40_migration(connection: &Connection) -> SqliteResult<()> {
    let transaction = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    transaction.execute_batch(MIGRATION_V40)?;
    // The write latch fence is installed per authoritative table; the new
    // table must fence like every other canonical table.
    for operation in ["insert", "update", "delete"] {
        transaction.execute_batch(&v12_fence_trigger("conversation_context_scope", operation).1)?;
    }
    transaction.execute("INSERT INTO schema_version (version) VALUES (40)", [])?;
    transaction.commit()
}

pub(super) fn v40_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 40 {
        return Ok(false);
    }
    let marker: (i64, i64, i64, i64) = connection.query_row(
        "SELECT COALESCE(MAX(version),0),COALESCE(MIN(version),0),COUNT(*),COALESCE(SUM(version),0) FROM schema_version",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    // The alternate marker covers production databases that skipped the
    // replay-fixture-only V19 migration (see v37/v38/v39 matchers).
    if !matches!(marker, (40, 1, 39, 801) | (40, 1, 40, 820)) {
        return Ok(false);
    }
    Ok(catalog_marker_matches(connection)?
        && inherited_credential_guards_match(connection)?
        && v37_structure_matches(connection)?
        && v40_catalog_matches(connection)?
        && project_workspace_schema::v36_receipt_table_matches(connection)?
        && project_workspace_schema::validation::global_command_triggers_match(connection)?
        && v39_lineage_table_matches(connection)?
        && v40_scope_table_matches(connection)?)
}

/// The V38 catalog check pins the exact table set, so the V40 marker reuses
/// the same extension walk with `conversation_context_scope` appended.
fn v40_catalog_matches(connection: &Connection) -> SqliteResult<bool> {
    v29_catalog_matches_with_extensions(
        connection,
        v35_operation_index_names(),
        &CredentialSchemaExtensions {
            tables: &[V33_TABLE, V35_TABLE, TABLE, "conversation_context_scope"],
            indexes: &[V33_INDEX],
            triggers: &[],
            replacements: &[],
        },
    )
}

pub(super) fn v40_scope_table_matches(connection: &Connection) -> SqliteResult<bool> {
    let actual: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
            ["conversation_context_scope"],
            |row| row.get(0),
        )
        .optional()?;
    let expected = MIGRATION_V40
        .split(';')
        .map(str::trim)
        .find(|statement| statement.starts_with("CREATE TABLE conversation_context_scope "))
        .map(str::to_owned);
    Ok(actual.is_some_and(|actual| {
        expected.is_some_and(|expected| normalize_ddl(&actual) == normalize_ddl(&expected))
    }))
}
