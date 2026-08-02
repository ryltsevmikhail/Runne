fn verify_exact_sql(
    conn: &Connection,
    object_type: &str,
    name: &str,
    supplied: &str,
    migration_prefix: &str,
) -> SqliteResult<()> {
    let actual = if supplied.is_empty() {
        conn.query_row(
            "SELECT sql FROM sqlite_master WHERE type = ?1 AND name = ?2",
            [object_type, name],
            |row| row.get::<_, String>(0),
        )?
    } else {
        supplied.to_owned()
    };
    let expected = MIGRATION_V1
        .split(';')
        .map(str::trim)
        .find(|statement| statement.starts_with(migration_prefix))
        .ok_or(rusqlite::Error::InvalidQuery)?;
    verify_normalized_sql(&actual, expected)
}

fn verify_authoritative_sql(
    conn: &Connection,
    object_type: &str,
    name: &str,
    expected: &str,
) -> SqliteResult<()> {
    let actual = conn.query_row(
        "SELECT sql FROM sqlite_master WHERE type = ?1 AND name = ?2",
        [object_type, name],
        |row| row.get::<_, String>(0),
    )?;
    verify_normalized_sql(&actual, expected)
}

fn verify_normalized_sql(actual: &str, expected: &str) -> SqliteResult<()> {
    if normalize_sql(actual) != normalize_sql(expected) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}

fn normalize_sql(sql: &str) -> String {
    let mut normalized = String::with_capacity(sql.len());
    let mut characters = sql.chars().peekable();
    let mut quote_terminator = None;

    while let Some(character) = characters.next() {
        match quote_terminator {
            Some(terminator) => {
                normalized.push(character);
                if character == terminator {
                    if characters.peek().is_some_and(|next| *next == terminator) {
                        if let Some(escaped_terminator) = characters.next() {
                            normalized.push(escaped_terminator);
                        }
                    } else {
                        quote_terminator = None;
                    }
                }
            }
            None if matches!(character, '\'' | '"' | '`') => {
                quote_terminator = Some(character);
                normalized.push(character);
            }
            None if character == '[' => {
                quote_terminator = Some(']');
                normalized.push(character);
            }
            None if character.is_whitespace() => {}
            None => normalized.extend(character.to_lowercase()),
        }
    }

    normalized
}

fn verify_index_columns(
    conn: &Connection,
    index: &str,
    expected: &[&str],
    unique: bool,
) -> SqliteResult<()> {
    let index_exists = conn
        .prepare("PRAGMA index_list(session_bindings)")?
        .query_map([], |row| {
            Ok((row.get::<_, String>(1)?, row.get::<_, i64>(2)?))
        })?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .any(|(name, actual_unique)| name == index && (actual_unique == 1) == unique);
    if !index_exists {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let columns = conn
        .prepare(&format!("PRAGMA index_info({index})"))?
        .query_map([], |row| row.get::<_, String>(2))?
        .collect::<Result<Vec<_>, _>>()?;
    if columns
        .iter()
        .map(String::as_str)
        .ne(expected.iter().copied())
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}

fn verify_pragmas(conn: &Connection) -> SqliteResult<()> {
    let journal: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    let synchronous: i64 = conn.query_row("PRAGMA synchronous", [], |row| row.get(0))?;
    let foreign_keys: i64 = conn.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    let busy_timeout: i64 = conn.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?;
    if !journal.eq_ignore_ascii_case("wal")
        || synchronous != 2
        || foreign_keys != 1
        || busy_timeout != 5_000
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    #[cfg(target_os = "macos")]
    {
        let fullfsync: i64 = conn.query_row("PRAGMA fullfsync", [], |row| row.get(0))?;
        if fullfsync != 1 {
            return Err(rusqlite::Error::InvalidQuery);
        }
    }
    Ok(())
}
