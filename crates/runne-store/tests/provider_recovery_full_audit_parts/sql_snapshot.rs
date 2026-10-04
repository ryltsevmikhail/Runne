use rusqlite::Connection;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct SqlSnapshot(pub(super) Vec<(String, Vec<Vec<String>>)>);

pub(super) fn sql_snapshot(connection: &Connection) -> SqlSnapshot {
    let mut tables = connection
        .prepare(
            "SELECT name FROM sqlite_schema
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
        )
        .unwrap();
    let tables = tables
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    SqlSnapshot(
        tables
            .into_iter()
            .map(|table| (table.clone(), sql_table_rows(connection, &table)))
            .collect(),
    )
}

pub(super) fn sql_table_rows(connection: &Connection, table: &str) -> Vec<Vec<String>> {
    let columns = connection
        .prepare(&format!("PRAGMA table_info(\"{table}\")"))
        .unwrap()
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let values = columns
        .iter()
        .map(|column| format!("quote(\"{column}\")"))
        .collect::<Vec<_>>()
        .join(", ");
    let order = (1..=columns.len())
        .map(|index| index.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let mut rows = connection
        .prepare(&format!(
            "SELECT {values} FROM \"{table}\" ORDER BY {order}"
        ))
        .unwrap();
    rows.query_map([], |row| {
        (0..columns.len())
            .map(|index| row.get::<_, String>(index))
            .collect()
    })
    .unwrap()
    .collect::<Result<Vec<_>, _>>()
    .unwrap()
}
