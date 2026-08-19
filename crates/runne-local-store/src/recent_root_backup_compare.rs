use super::recent_root_schema_tables::{V4_TABLES, expected_columns};
use super::{Connection, StoreOpenError};
use rusqlite::types::ValueRef;

pub fn v4_tables_equal(connection: &Connection) -> Result<bool, StoreOpenError> {
    for table in V4_TABLES {
        if !table_equal(connection, table)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn table_equal(connection: &Connection, table: &str) -> Result<bool, StoreOpenError> {
    let columns = columns(table).ok_or(StoreOpenError::PreV5BackupSourceMismatch)?;
    let query = select_ordered(table, &columns);
    let mut main = connection.prepare(&query.replace("{schema}", "main"))?;
    let mut backup = connection.prepare(&query.replace("{schema}", "pre_v5_backup"))?;
    let mut main_rows = main.query([])?;
    let mut backup_rows = backup.query([])?;
    loop {
        match (main_rows.next()?, backup_rows.next()?) {
            (None, None) => return Ok(true),
            (Some(main), Some(backup)) if encode_row(main)? == encode_row(backup)? => {}
            _ => return Ok(false),
        }
    }
}

fn select_ordered(table: &str, columns: &[&str]) -> String {
    let columns = columns
        .iter()
        .map(|column| format!("\"{column}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let order = columns
        .split(", ")
        .map(|column| format!("typeof({column}) COLLATE BINARY, length(CAST({column} AS BLOB)), hex(CAST({column} AS BLOB)) COLLATE BINARY"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("SELECT {columns} FROM {{schema}}.\"{table}\" ORDER BY {order}")
}

fn columns(table: &str) -> Option<Vec<&'static str>> {
    if table == "projects" {
        return Some(vec!["id", "name", "path", "last_opened_at"]);
    }
    expected_columns(table).map(<[&str]>::to_vec)
}

fn encode_row(row: &rusqlite::Row<'_>) -> Result<Vec<u8>, rusqlite::Error> {
    let mut output = Vec::new();
    for column in 0..row.as_ref().column_count() {
        encode(&mut output, row.get_ref(column)?);
    }
    Ok(output)
}

fn encode(output: &mut Vec<u8>, value: ValueRef<'_>) {
    match value {
        ValueRef::Null => output.push(b'n'),
        ValueRef::Integer(value) => {
            output.push(b'i');
            output.extend(value.to_be_bytes());
        }
        ValueRef::Real(value) => {
            output.push(b'r');
            output.extend(value.to_bits().to_be_bytes());
        }
        ValueRef::Text(value) => bytes(output, b't', value),
        ValueRef::Blob(value) => bytes(output, b'b', value),
    }
}

fn bytes(output: &mut Vec<u8>, tag: u8, value: &[u8]) {
    output.push(tag);
    output.extend(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    output.extend(value);
}

#[cfg(test)]
mod tests {
    use super::{Connection, encode};

    fn canonical(connection: &Connection, sql: &str) -> Vec<u8> {
        connection
            .query_row(sql, [], |row| {
                let mut output = Vec::new();
                encode(&mut output, row.get_ref(0)?);
                Ok(output)
            })
            .expect("canonical value")
    }

    #[test]
    fn canonical_values_ignore_sql_collation_and_preserve_type_and_bytes() {
        let connection = Connection::open_in_memory().expect("memory database");
        assert_ne!(
            canonical(&connection, "SELECT 'Alpha' COLLATE NOCASE"),
            canonical(&connection, "SELECT 'alpha' COLLATE NOCASE")
        );
        assert_ne!(
            canonical(&connection, "SELECT NULL"),
            canonical(&connection, "SELECT X''")
        );
        assert_ne!(
            canonical(&connection, "SELECT X'31'"),
            canonical(&connection, "SELECT '1'")
        );
        assert_ne!(
            canonical(&connection, "SELECT 'a' || char(0)"),
            canonical(&connection, "SELECT 'a'")
        );
    }
}
