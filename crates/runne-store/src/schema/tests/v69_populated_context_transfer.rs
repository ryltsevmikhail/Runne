type RawSnapshot = std::collections::BTreeMap<String, (Vec<String>, Vec<Vec<Value>>)>;
fn quoted(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}
fn columns(c: &Connection, table: &str) -> Vec<String> {
    c.prepare(&format!("PRAGMA table_info({})", quoted(table)))
        .unwrap()
        .query_map([], |r| r.get(1))
        .unwrap()
        .collect::<SqliteResult<_>>()
        .unwrap()
}
fn rows(c: &Connection, table: &str, columns: &[String]) -> Vec<Vec<Value>> {
    let sql = format!(
        "SELECT {} FROM {}",
        columns
            .iter()
            .map(|v| quoted(v))
            .collect::<Vec<_>>()
            .join(","),
        quoted(table)
    );
    let mut values: Vec<Vec<Value>> = c
        .prepare(&sql)
        .unwrap()
        .query_map([], |r| (0..columns.len()).map(|i| r.get(i)).collect())
        .unwrap()
        .collect::<SqliteResult<_>>()
        .unwrap();
    values.sort_by_key(|v| format!("{v:?}"));
    values
}
fn snapshot(source: &Connection, old_schema: &Connection) -> RawSnapshot {
    let tables: Vec<String> = old_schema.prepare(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name!='schema_version' ORDER BY name"
    ).unwrap().query_map([], |r| r.get(0)).unwrap().collect::<SqliteResult<_>>().unwrap();
    tables
        .into_iter()
        .map(|table| {
            let cols = columns(old_schema, &table);
            let data = rows(source, &table, &cols);
            (table, (cols, data))
        })
        .collect()
}
fn snapshot_with_columns(c: &Connection, old: &RawSnapshot) -> RawSnapshot {
    old.iter()
        .map(|(table, (cols, _))| (table.clone(), (cols.clone(), rows(c, table, cols))))
        .collect()
}
fn transfer(destination: &Connection, data: &RawSnapshot) {
    // Retry dependency-blocked INSERTs only. Never disable/drop a guard or FK.
    // Defaults already present in a fresh schema are checked by exact snapshot.
    let mut pending = Vec::new();
    for (table, (cols, rows)) in data {
        let sql = format!(
            "INSERT OR IGNORE INTO {}({}) VALUES({})",
            quoted(table),
            cols.iter().map(|v| quoted(v)).collect::<Vec<_>>().join(","),
            vec!["?"; cols.len()].join(",")
        );
        let present = self::rows(destination, table, cols);
        for row in rows {
            if present.contains(row) {
                continue;
            }
            let mut initial = row.clone();
            if table == "taskrun_local_command_attempts" {
                for (i, col) in cols.iter().enumerate() {
                    match col.as_str() {
                        "state" => initial[i] = Value::Text("preflight".into()),
                        "attempt_id"
                        | "node_id"
                        | "node_epoch"
                        | "fence"
                        | "managed_area_identity" => initial[i] = Value::Null,
                        _ => {}
                    }
                }
            }
            pending.push((table.clone(), sql.clone(), initial));
        }
    }
    while !pending.is_empty() {
        let count = pending.len();
        let mut blocked = Vec::new();
        let mut failures = Vec::new();
        for (table, sql, row) in pending {
            match destination.execute(&sql, rusqlite::params_from_iter(row.iter())) {
                Ok(_) => {}
                Err(error) => {
                    failures.push(format!("{table}: {error}"));
                    blocked.push((table, sql, row));
                }
            }
        }
        assert!(
            blocked.len() < count,
            "fixture row dependencies cannot be seeded: {failures:?}"
        );
        pending = blocked;
    }
    // Route guard sees preflight first; only then restore captured attempt data
    // through the existing one-way identity/state UPDATE guards.
    let (cols, attempts) = &data["taskrun_local_command_attempts"];
    for row in attempts {
        let changed: Vec<usize> = cols
            .iter()
            .enumerate()
            .filter_map(|(i, col)| {
                matches!(
                    col.as_str(),
                    "state"
                        | "attempt_id"
                        | "node_id"
                        | "node_epoch"
                        | "fence"
                        | "managed_area_identity"
                )
                .then_some(i)
            })
            .collect();
        let sql = format!(
            "UPDATE taskrun_local_command_attempts SET {} WHERE taskrun_id=?",
            changed
                .iter()
                .map(|i| format!("{}=?", quoted(&cols[*i])))
                .collect::<Vec<_>>()
                .join(",")
        );
        let mut values: Vec<Value> = changed.iter().map(|i| row[*i].clone()).collect();
        values.push(row[cols.iter().position(|c| c == "taskrun_id").unwrap()].clone());
        destination
            .execute(&sql, rusqlite::params_from_iter(values.iter()))
            .unwrap();
    }
    // This mutable sequence singleton starts empty in the destination.
    let (cols, values) = &data["event_log_state"];
    for row in values {
        let sql = format!(
            "UPDATE event_log_state SET {}",
            cols.iter()
                .map(|c| format!("{}=?", quoted(c)))
                .collect::<Vec<_>>()
                .join(",")
        );
        destination
            .execute(&sql, rusqlite::params_from_iter(row.iter()))
            .unwrap();
    }
    let foreign_keys: i64 = destination
        .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
        .unwrap();
    assert_eq!(foreign_keys, 1);
    let violations: i64 = destination
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(violations, 0);
}
