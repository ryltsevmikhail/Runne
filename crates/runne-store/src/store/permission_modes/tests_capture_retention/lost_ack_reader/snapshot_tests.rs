//! Source-only fresh in-memory SQLite regressions; execution NOTRUN.
use super::{capture_connection, Limits};
use rusqlite::Connection;

fn database(sql: &str) -> Connection {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch(sql).unwrap();
    c.execute_batch("PRAGMA query_only=ON").unwrap();
    c
}
fn change(c: &Connection, sql: &str) {
    c.execute_batch("PRAGMA query_only=OFF").unwrap();
    c.execute_batch(sql).unwrap();
    c.execute_batch("PRAGMA query_only=ON").unwrap();
}
fn snap(c: &mut Connection) -> super::Snapshot {
    capture_connection(c, Limits::fixture()).unwrap()
}

// Break: a missing ordinary history row is ignored when receipt counts match.
#[test]
fn detects_nonreceipt_history_change() {
    let mut c = database("CREATE TABLE history(v); INSERT INTO history VALUES(7);");
    let before = snap(&mut c);
    change(&c,"UPDATE history SET v=8");
    assert_ne!(snap(&mut c),before);
}

// Break: NULL, empty TEXT and empty BLOB collapse in an ambiguous serializer.
#[test]
fn distinguishes_null_empty_text_and_empty_blob() {
    let mut c = database("CREATE TABLE t(v); INSERT INTO t VALUES(NULL);");
    let null = snap(&mut c);
    change(&c,"UPDATE t SET v=''");
    let text = snap(&mut c);
    change(&c,"UPDATE t SET v=X''");
    let blob = snap(&mut c);
    assert_ne!(null,text);assert_ne!(text,blob);assert_ne!(null,blob);
}

// Break: equal payload values hide deletion of a distinct identified row.
#[test]
fn detects_deletion_among_same_payload_rows() {
    let mut c = database("CREATE TABLE t(v); INSERT INTO t VALUES(7),(7);");
    let before = snap(&mut c);
    change(&c,"DELETE FROM t WHERE rowid=(SELECT min(rowid) FROM t)");
    assert_ne!(snap(&mut c),before);
}

// Break: harmless retrieval order becomes part of logical history equality.
#[test]
fn ignores_physical_row_order() {
    let mut c = database("CREATE TABLE t(v); INSERT INTO t VALUES(1),(2);");
    let before = snap(&mut c);
    c.execute_batch("PRAGMA reverse_unordered_selects=ON;").unwrap();
    assert_eq!(snap(&mut c),before);
}

// Break: an empty added table or header schema version is invisible.
#[test]
fn detects_empty_table_and_user_version_change() {
    let mut c = database("CREATE TABLE t(v);");
    let before = snap(&mut c);
    change(&c,"CREATE TABLE added(v);");
    let added = snap(&mut c);assert_ne!(added,before);
    change(&c,"PRAGMA user_version=69;");
    assert_ne!(snap(&mut c),added);
}

// Break: implicit numeric conversion equates INTEGER1 and REAL1.0.
#[test]
fn preserves_sqlite_storage_class() {
    let mut c = database("CREATE TABLE t(v); INSERT INTO t VALUES(1);");
    let integer = snap(&mut c);
    change(&c,"UPDATE t SET v=1.0;");
    assert_ne!(snap(&mut c),integer);
}

// Break: a fresh writer connection is silently advertised as an oracle reader.
#[test]
fn refuses_query_only_off_without_toggling_it() {
    let mut c = Connection::open_in_memory().unwrap();
    assert!(capture_connection(&mut c,Limits::fixture()).is_err());
    let fence:i64 = c.query_row("PRAGMA query_only",[],|r|r.get(0)).unwrap();
    assert_eq!(fence,0);
}

// Break: byte/row/table/column ceilings yield a silently truncated success.
#[test]
fn refuses_each_budget_without_returning_partial_snapshot() {
    let mut c = database("CREATE TABLE t(a,b); INSERT INTO t VALUES('payload',7);");
    let before = snap(&mut c);
    for limits in [Limits{bytes:1,..Limits::fixture()},
                   Limits{rows:0,..Limits::fixture()},
                   Limits{tables:0,..Limits::fixture()},
                   Limits{columns:1,..Limits::fixture()}] {
        assert!(capture_connection(&mut c,limits).is_err());
        assert!(c.is_autocommit());
    }
    assert_eq!(snap(&mut c),before); // usable after failed transactions
}

// Break: table names are interpolated without identifier quoting.
#[test]
fn handles_quoted_table_names() {
    let mut c = database("CREATE TABLE \"odd\"\"table\"(v); INSERT INTO \"odd\"\"table\" VALUES(7);");
    let before = snap(&mut c);
    change(&c,"UPDATE \"odd\"\"table\" SET v=8;");
    assert_ne!(snap(&mut c),before);
}

// Break: hidden row identity is silently ignored in a rowid table.
#[test]
fn detects_hidden_rowid_change() {
    let mut c = database("CREATE TABLE t(v); INSERT INTO t(rowid,v) VALUES(7,'same');");
    let before = snap(&mut c);
    change(&c,"UPDATE t SET rowid=8;");
    assert_ne!(snap(&mut c),before);
}

// Break: WITHOUT ROWID tables are skipped or forced through an invalid rowid query.
#[test]
fn includes_without_rowid_tables() {
    let mut c = database("CREATE TABLE t(k TEXT PRIMARY KEY,v) WITHOUT ROWID; INSERT INTO t VALUES('k',7);");
    let before = snap(&mut c);
    change(&c,"UPDATE t SET v=8;");
    assert_ne!(snap(&mut c),before);
}

// Break: a declared rowid column hides real row identity.
#[test]
fn selects_an_unshadowed_rowid_alias() {
    let mut c = database("CREATE TABLE t(rowid TEXT,v); INSERT INTO t(_rowid_,rowid,v) VALUES(7,'shown',1);");
    let before = snap(&mut c);
    change(&c,"UPDATE t SET _rowid_=8;");
    assert_ne!(snap(&mut c),before);
}

// Break: table payload bytes bypass the shared byte budget after small catalog rows.
#[test]
fn refuses_oversized_table_payload() {
    let mut c = database("CREATE TABLE t(v); INSERT INTO t VALUES(zeroblob(1024));");
    assert!(capture_connection(&mut c,Limits::fixture()).is_ok());
    assert!(capture_connection(&mut c,Limits{bytes:512,..Limits::fixture()}).is_err());
    assert!(c.is_autocommit());
    assert_eq!(c.query_row("SELECT length(v) FROM t",[],|r|r.get::<_,i64>(0)).unwrap(),1024);
}

// Break: oracle nests into or rolls back a caller's unrelated transaction.
#[test]
fn refuses_existing_transaction_without_consuming_it() {
    let mut c = database("CREATE TABLE t(v);");
    c.execute_batch("BEGIN").unwrap();
    assert!(capture_connection(&mut c,Limits::fixture()).is_err());
    assert!(!c.is_autocommit());
    c.execute_batch("ROLLBACK").unwrap();
    assert!(capture_connection(&mut c,Limits::fixture()).is_ok());
}

// Break: invalid UTF-8 TEXT bytes are dropped or converted into a BLOB.
#[test]
fn preserves_non_utf8_text_storage_class() {
    let mut c = database("CREATE TABLE t(v); INSERT INTO t VALUES(CAST(X'80ff' AS TEXT));");
    let text = snap(&mut c);
    change(&c,"UPDATE t SET v=X'80ff'");
    assert_ne!(snap(&mut c),text);
}

// Break: inaccessible implicit row identity is silently omitted.
#[test]
fn refuses_when_every_rowid_alias_is_shadowed() {
    let mut c = database("CREATE TABLE t(rowid,_rowid_); INSERT INTO t VALUES(1,2);");
    assert!(capture_connection(&mut c,Limits::fixture()).is_ok());
    change(&c,"ALTER TABLE t ADD COLUMN oid DEFAULT 3;");
    assert!(capture_connection(&mut c,Limits::fixture()).is_err());
    assert!(c.is_autocommit());
}

// Break: data-table columns bypass limits while four-column catalog still fits.
#[test]
fn refuses_data_columns_after_catalog_fits() {
    let mut c = database("CREATE TABLE t(a,b,c,d,e); INSERT INTO t VALUES(1,2,3,4,5);");
    // Five declared values + real hidden identity = six selected fields.
    assert!(capture_connection(&mut c,Limits{columns:6,..Limits::fixture()}).is_ok());
    assert!(capture_connection(&mut c,Limits{columns:5,..Limits::fixture()}).is_err());
    assert!(c.is_autocommit());
}

// Break: successful observation turns off the caller's reader fence or leaves a tx.
#[test]
fn successful_snapshot_preserves_fence_and_autocommit() {
    let mut c = database("CREATE TABLE t(v); INSERT INTO t VALUES(7);");
    assert!(capture_connection(&mut c,Limits::fixture()).is_ok());
    assert!(c.is_autocommit());
    assert_eq!(c.query_row("PRAGMA query_only",[],|r|r.get::<_,i64>(0)).unwrap(),1);
    assert!(c.execute("UPDATE t SET v=8",[]).is_err());
    assert_eq!(c.query_row("SELECT v FROM t",[],|r|r.get::<_,i64>(0)).unwrap(),7);
}

// Break: REAL values are truncated to integer even though storage tags survive.
#[test]
fn distinguishes_fractional_real_values_with_same_integer_part() {
    let mut c = database("CREATE TABLE t(v); INSERT INTO t VALUES(1.5);");
    let before = snap(&mut c);
    change(&c,"UPDATE t SET v=1.75;");
    assert_ne!(snap(&mut c),before);
}

// Break: application identity changes are omitted from logical baseline.
#[test]
fn detects_application_id_change() {
    let mut c = database("CREATE TABLE t(v); PRAGMA application_id=7;");
    let before = snap(&mut c);
    change(&c,"PRAGMA application_id=8;");
    assert_ne!(snap(&mut c),before);
}

// Break: caller raises a test-only limit and silently escapes the frozen ceiling.
#[test]
fn refuses_raised_limits() {
    let mut c = database("CREATE TABLE t(v);");
    assert!(capture_connection(&mut c,Limits::fixture()).is_ok());
    let cap = Limits::fixture();
    for limits in [Limits{tables:cap.tables+1,..cap},
                   Limits{rows:cap.rows+1,..cap},
                   Limits{columns:cap.columns+1,..cap},
                   Limits{bytes:cap.bytes+1,..cap}] {
        assert!(capture_connection(&mut c,limits).is_err());
        assert!(c.is_autocommit());
    }
}
