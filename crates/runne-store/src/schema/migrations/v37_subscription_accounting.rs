const ADMISSIONS: &str = "provider_execution_admissions";
const RESERVATIONS: &str = "provider_budget_reservations";

pub(super) fn apply_v37_migration(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch("PRAGMA foreign_keys=OFF; PRAGMA legacy_alter_table=ON;")?;
    let result = (|| {
        let tx = Transaction::new_unchecked(conn, TransactionBehavior::Exclusive)?;
        rebuild_table(
            &tx,
            ADMISSIONS,
            "max_cost_micros INTEGER NOT NULL CHECK(max_cost_micros > 0), currency TEXT NOT NULL CHECK(length(currency) = 3)",
            "max_cost_micros INTEGER NOT NULL CHECK(max_cost_micros >= 0), currency TEXT NOT NULL CHECK(length(currency) = 3 AND (max_cost_micros > 0 OR currency = 'XXX'))",
        )?;
        rebuild_table(
            &tx,
            RESERVATIONS,
            "amount INTEGER NOT NULL CHECK(amount > 0)",
            "amount INTEGER NOT NULL CHECK(amount > 0 OR (dimension = 2 AND amount = 0))",
        )?;
        tx.execute("INSERT INTO schema_version (version) VALUES (37)", [])?;
        tx.commit()
    })();
    let restore = conn.execute_batch("PRAGMA legacy_alter_table=OFF; PRAGMA foreign_keys=ON;");
    result.and(restore)
}

fn rebuild_table(
    tx: &Transaction<'_>,
    table: &str,
    old_fragment: &str,
    new_fragment: &str,
) -> SqliteResult<()> {
    let old = format!("{table}_v36");
    let objects = table_objects(tx, table)?;
    tx.execute(&format!("ALTER TABLE {table} RENAME TO {old}"), [])?;
    let source: String = tx.query_row(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [&old],
        |row| row.get(0),
    )?;
    if normalized_contains(&source, new_fragment) {
        return Ok(());
    }
    let renamed = source
        .replace(
            &format!("CREATE TABLE {old}"),
            &format!("CREATE TABLE {table}"),
        )
        .replace(
            &format!("CREATE TABLE \"{old}\""),
            &format!("CREATE TABLE {table}"),
        );
    let rewritten = replace_normalized(&renamed, old_fragment, new_fragment);
    if rewritten == renamed {
        return Err(rusqlite::Error::InvalidQuery);
    }
    tx.execute_batch(&rewritten)?;
    tx.execute(&format!("INSERT INTO {table} SELECT * FROM {old}"), [])?;
    tx.execute(&format!("DROP TABLE {old}"), [])?;
    for (_, _, sql) in objects {
        tx.execute_batch(&sql)?;
    }
    Ok(())
}

fn replace_normalized(source: &str, old: &str, new: &str) -> String {
    let mut normalized = String::with_capacity(source.len());
    let mut offsets = Vec::with_capacity(source.len());
    for (offset, character) in source.char_indices() {
        if !character.is_whitespace() {
            for byte in character.to_lowercase().to_string().bytes() {
                normalized.push(byte as char);
                offsets.push(offset);
            }
        }
    }
    let old_normalized: String = old
        .chars()
        .filter(|character| !character.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect();
    let Some(start) = normalized.find(&old_normalized) else {
        return source.to_owned();
    };
    let end = offsets[start + old_normalized.len() - 1]
        + source[offsets[start + old_normalized.len() - 1]..]
            .chars()
            .next()
            .unwrap()
            .len_utf8();
    format!("{}{}{}", &source[..offsets[start]], new, &source[end..])
}

fn normalized_contains(source: &str, fragment: &str) -> bool {
    let normalized = |value: &str| {
        value
            .chars()
            .filter(|character| !character.is_whitespace())
            .flat_map(char::to_lowercase)
            .collect::<String>()
    };
    normalized(source).contains(&normalized(fragment))
}

fn table_objects(tx: &Transaction<'_>, table: &str) -> SqliteResult<Vec<(String, String, String)>> {
    tx.prepare(
        "SELECT type, name, sql FROM sqlite_master
         WHERE tbl_name = ?1 AND type IN ('index', 'trigger') AND sql IS NOT NULL
         ORDER BY type, name",
    )?
    .query_map([table], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
    .collect()
}

pub(super) fn v37_matches(conn: &Connection, version: i64) -> SqliteResult<bool> {
    if version != 37 {
        return Ok(false);
    }
    let marker: (i64, i64, i64, i64) = conn.query_row(
        "SELECT COALESCE(MAX(version),0),COALESCE(MIN(version),0),COUNT(*),COALESCE(SUM(version),0) FROM schema_version",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    if !matches!(marker, (37, 1, 36, 684) | (37, 1, 37, 703)) {
        return Ok(false);
    }
    Ok(catalog_marker_matches(conn)?
        && inherited_credential_guards_match(conn)?
        && v37_structure_matches(conn)?)
}

pub(super) fn v37_structure_matches(conn: &Connection) -> SqliteResult<bool> {
    let inherited = v35_structure_matches_with_v36_receipt(conn, true, false)?;
    let reservation = migrated_table_matches(
        conn,
        RESERVATIONS,
        "amount INTEGER NOT NULL CHECK(amount > 0 OR (dimension = 2 AND amount = 0))",
    )?;
    // The v37 rebuild rewrites only the two v13 accounting tables, so the
    // alternate structure path must still enforce the untouched inherited
    // contract: the v9/v12 base (strict v9 table DDL, idx_evidence_run
    // semantics, schema_lineage marker, upgrade fence/latch), the unchanged
    // v13 tables, the exact v14 authority-state/admissions DDL, and the v20
    // snapshot table, index, and bind triggers.
    let base = if inherited {
        true
    } else {
        let v12 = provider_v12_core_matches(conn)?;
        let accounting = v37_accounting_tables_match(conn)?;
        v12
            && accounting
            && v13_unchanged_tables_match_for_v37(conn)?
            && provider_schema::v14_base_matches_for_v37(conn, v12, accounting)?
            && replay_promotion_snapshot_schema::v20_base_matches(conn, false)?
    };
    Ok(base && reservation)
}

fn migrated_table_matches(conn: &Connection, table: &str, replacement: &str) -> SqliteResult<bool> {
    let actual = table_sql(conn, table)?;
    let expected = MIGRATION_V13
        .split(';')
        .map(str::trim)
        .find(|sql| sql.starts_with(&format!("CREATE TABLE {table} ")))
        .map(|sql| sql.replace(
            if table == ADMISSIONS {
                "max_cost_micros INTEGER NOT NULL CHECK(max_cost_micros > 0), currency TEXT NOT NULL CHECK(length(currency) = 3)"
            } else {
                "amount INTEGER NOT NULL CHECK(amount > 0)"
            },
            replacement,
        ));
    Ok(actual
        .zip(expected)
        .is_some_and(|(actual, expected)| normalize_ddl(&actual) == normalize_ddl(&expected)))
}

fn table_sql(conn: &Connection, table: &str) -> SqliteResult<Option<String>> {
    conn.query_row(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [table],
        |row| row.get(0),
    )
    .optional()
}
