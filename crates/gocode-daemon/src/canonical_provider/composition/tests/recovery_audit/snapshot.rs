use std::collections::BTreeMap;

pub(super) type Snapshot = BTreeMap<String, Vec<Vec<String>>>;

pub(super) fn snapshot(path: &str) -> Snapshot {
    let connection = rusqlite::Connection::open(path).unwrap();
    connection.execute_batch("PRAGMA query_only = ON;").unwrap();
    let tables = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    tables
        .into_iter()
        .map(|table| {
            let columns = table_columns_from(&connection, &table);
            let values = columns
                .iter()
                .map(|column| format!("quote(\"{column}\")"))
                .collect::<Vec<_>>()
                .join(", ");
            let order = (1..=columns.len())
                .map(|index| index.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let rows = connection
                .prepare(&format!(
                    "SELECT {values} FROM \"{table}\" ORDER BY {order}"
                ))
                .unwrap()
                .query_map([], |row| {
                    (0..columns.len())
                        .map(|index| row.get::<_, String>(index))
                        .collect()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            (table, rows)
        })
        .collect()
}

pub(super) fn table_columns(path: &str, table: &str) -> Vec<String> {
    table_columns_from(&rusqlite::Connection::open(path).unwrap(), table)
}

fn table_columns_from(connection: &rusqlite::Connection, table: &str) -> Vec<String> {
    connection
        .prepare(&format!("PRAGMA table_info(\"{table}\")"))
        .unwrap()
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
}

pub(super) fn assert_unchanged_except(before: &Snapshot, after: &Snapshot, allowed: &[&str]) {
    assert_eq!(
        before.keys().collect::<Vec<_>>(),
        after.keys().collect::<Vec<_>>()
    );
    for (table, rows) in before {
        if !allowed.contains(&table.as_str()) {
            assert_eq!(
                after.get(table),
                Some(rows),
                "unexpected mutation in {table}"
            );
        }
    }
}
