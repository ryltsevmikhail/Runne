use super::support::{Fixture, Storage};

#[test]
fn new_file_stores_nullable_original_context_pair() {
    let fixture = Fixture::new(Storage::File);
    let writer = fixture.store().inner.writer.lock().unwrap();
    let mut statement = writer
        .prepare("PRAGMA table_info(x2_permission_bindings)")
        .unwrap();
    let columns = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(
        !columns.is_empty(),
        "existing binding table must be observable"
    );
    for name in ["retained_context", "retained_context_digest"] {
        assert_eq!(
            columns.iter().find(|column| column.0 == name),
            Some(&(name.to_owned(), "BLOB".to_owned(), 0, None)),
            "new captures require nullable original-context storage without defaults"
        );
    }
}

#[test]
fn new_file_reaches_original_context_schema_version() {
    let fixture = Fixture::new(Storage::File);
    let version: i64 = fixture
        .store()
        .inner
        .writer
        .lock()
        .unwrap()
        .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        version, 71,
        "current schema includes original-context migration"
    );
}
