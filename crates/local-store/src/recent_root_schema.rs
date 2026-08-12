use super::recent_root_schema_indices::expected_indices;
use super::recent_root_schema_normalize::normalize_sql;
use super::recent_root_schema_tables::{
    TABLES, V4_TABLES, expected_columns, expected_index_count, expected_sql_hash,
};
use super::{Connection, Digest, LocalStore, Sha256, StoreOpenError};

impl LocalStore {
    pub(super) fn validate_v5_schema(&self) -> Result<(), StoreOpenError> {
        validate_v5_schema(&self.connection)
    }
}

pub fn validate_v4_projects(connection: &Connection) -> Result<(), StoreOpenError> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let meta = meta_version(connection)?;
    let mut tables = table_names(connection)?;
    tables.sort_unstable();
    let mut expected = V4_TABLES.to_vec();
    expected.sort_unstable();
    if version != 4
        || meta != (1, 4, 1, 1)
        || tables != expected
        || !valid_tables(connection, 4, &V4_TABLES)?
        || !valid_v4_projects_columns(connection)?
        || !strict_table(connection, "projects")?
        || unique_index_count(connection, "projects")? != 1
        || schema_object_count(connection, "trigger", "projects")? != 0
        || foreign_key_count(connection, "projects")? != 0
        || connection.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type IN ('view', 'trigger') AND sql LIKE '%projects%'",
            [],
            |row| row.get::<_, i64>(0),
        )? != 0
        || schema_object_count(connection, "view", "")? != 0
    {
        return Err(StoreOpenError::SchemaCorrupt);
    }
    Ok(())
}

pub fn validate_v5_schema(connection: &Connection) -> Result<(), StoreOpenError> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let meta = meta_version(connection)?;
    let mut tables = table_names(connection)?;
    tables.sort_unstable();
    let mut expected = TABLES.to_vec();
    expected.sort_unstable();
    let valid_tables = valid_tables(connection, 5, &TABLES)?;
    if version != 5
        || meta != (1, 5, 1, 1)
        || tables != expected
        || !valid_tables
        || schema_object_count(connection, "trigger", "")? != 0
        || schema_object_count(connection, "view", "")? != 0
        || connection.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'index' AND sql IS NOT NULL",
            [],
            |row| row.get::<_, i64>(0),
        )? != 0
    {
        return Err(StoreOpenError::SchemaCorrupt);
    }
    Ok(())
}

fn meta_version(connection: &Connection) -> Result<(i64, i64, i64, i64), StoreOpenError> {
    connection
        .query_row(
            "SELECT COUNT(*), COALESCE(MIN(schema_version), 0), COALESCE(MIN(singleton), 0), COALESCE(MAX(singleton), 0) FROM meta",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .map_err(StoreOpenError::from)
}

fn valid_tables(
    connection: &Connection,
    schema_version: i64,
    tables: &[&str],
) -> Result<bool, StoreOpenError> {
    for table in tables {
        if *table == "projects" {
            continue;
        }
        let Some(expected) = expected_columns(table) else {
            return Ok(false);
        };
        let actual = columns(connection, table)?;
        if !actual
            .iter()
            .map(String::as_str)
            .eq(expected.iter().copied())
            || !strict_table(connection, table)?
            || foreign_key_count(connection, table)? != 0
            || automatic_index_count(connection, table)? != expected_index_count(table)
            || !table_sql_matches(connection, schema_version, table)?
            || !indices_match(connection, table)?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn indices_match(connection: &Connection, table: &str) -> Result<bool, StoreOpenError> {
    let Some(expected) = expected_indices(table) else {
        return Ok(false);
    };
    let mut statement = connection.prepare(
        "SELECT name, \"unique\", origin, partial FROM pragma_index_list(?1) WHERE origin IN ('pk', 'u')",
    )?;
    let mut actual = statement
        .query_map([table], |row| {
            let name: String = row.get(0)?;
            let unique: i64 = row.get(1)?;
            let origin: String = row.get(2)?;
            let partial: i64 = row.get(3)?;
            index_signature(connection, &name, unique, &origin, partial)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    actual.sort_unstable();
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    Ok(actual == expected)
}

fn index_signature(
    connection: &Connection,
    index: &str,
    unique: i64,
    origin: &str,
    partial: i64,
) -> rusqlite::Result<String> {
    let mut statement = connection.prepare(
        "SELECT cid, name, desc, coll, \"key\" FROM pragma_index_xinfo(?1) WHERE \"key\" = 1 ORDER BY seqno",
    )?;
    let columns = statement
        .query_map([index], |row| {
            Ok(format!(
                "{}:{}:{}:{}:{}",
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(format!("{origin}:{unique}:{partial}:{}", columns.join(",")))
}

fn table_sql_matches(
    connection: &Connection,
    schema_version: i64,
    table: &str,
) -> Result<bool, StoreOpenError> {
    let Some(expected) = expected_sql_hash(schema_version, table) else {
        return Ok(true);
    };
    let sql: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = ?1",
        [table],
        |row| row.get(0),
    )?;
    let normalized = normalize_sql(&sql);
    Ok(format!("{:x}", Sha256::digest(normalized)) == expected)
}

fn valid_v4_projects_columns(connection: &Connection) -> Result<bool, StoreOpenError> {
    let mut statement = connection.prepare(
        "SELECT name, type, \"notnull\", pk FROM pragma_table_info('projects') ORDER BY cid",
    )?;
    let columns = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(columns
        == [
            ("id".into(), "INTEGER".into(), 1, 1),
            ("name".into(), "TEXT".into(), 1, 0),
            ("path".into(), "TEXT".into(), 1, 0),
            ("last_opened_at".into(), "INTEGER".into(), 1, 0),
        ]
        && table_sql_matches(connection, 4, "projects")?)
}

fn columns(connection: &Connection, table: &str) -> Result<Vec<String>, StoreOpenError> {
    let mut statement =
        connection.prepare("SELECT name FROM pragma_table_info(?1) ORDER BY cid")?;
    statement
        .query_map([table], |row| row.get(0))?
        .collect::<Result<_, _>>()
        .map_err(StoreOpenError::from)
}

fn table_names(connection: &Connection) -> Result<Vec<String>, StoreOpenError> {
    let mut statement = connection.prepare(
        "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
    )?;
    statement
        .query_map([], |row| row.get(0))?
        .collect::<Result<_, _>>()
        .map_err(StoreOpenError::from)
}

fn strict_table(connection: &Connection, table: &str) -> Result<bool, StoreOpenError> {
    connection
        .query_row(
            "SELECT strict FROM pragma_table_list WHERE name = ?1",
            [table],
            |row| row.get(0),
        )
        .map_err(StoreOpenError::from)
}

fn schema_object_count(
    connection: &Connection,
    object_type: &str,
    table: &str,
) -> Result<i64, StoreOpenError> {
    connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type = ?1 AND (?2 = '' OR tbl_name = ?2)",
            [object_type, table],
            |row| row.get(0),
        )
        .map_err(StoreOpenError::from)
}

fn foreign_key_count(connection: &Connection, table: &str) -> Result<i64, StoreOpenError> {
    connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_foreign_key_list(?1)",
            [table],
            |row| row.get(0),
        )
        .map_err(StoreOpenError::from)
}

fn unique_index_count(connection: &Connection, table: &str) -> Result<i64, StoreOpenError> {
    connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_index_list(?1) WHERE \"unique\" = 1 AND origin = 'u'",
            [table],
            |row| row.get(0),
        )
        .map_err(StoreOpenError::from)
}

fn automatic_index_count(connection: &Connection, table: &str) -> Result<i64, StoreOpenError> {
    connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_index_list(?1) WHERE origin IN ('pk', 'u')",
            [table],
            |row| row.get(0),
        )
        .map_err(StoreOpenError::from)
}
