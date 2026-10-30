//! Synthetic SQL source tests only; not migrated/native fixtures. NOTRUN.
use super::*;
use rusqlite::params;
fn intent() -> ReceiptIntent<'static> {
    ReceiptIntent { command:[7;16],task:[9;16],authority:"ra",principal:"p",
        key:b"k",fingerprint:[3;32],version:5 }
}
pub(super) fn fixture() -> Connection {
    let c=Connection::open_in_memory().unwrap();
    // No constraints: intentional synthetic corrupt/cardinality controls.
    c.execute_batch("CREATE TABLE command_receipts(command_id,idempotency_scope_bytes,
        idempotency_key,fingerprint,command_outcome,committed_at);
        CREATE TABLE history(n INTEGER); INSERT INTO history VALUES(7);").unwrap();
    let mut scope=vec![0,1,0,2,b'r',b'a',0,1,b'p',5,1];
    scope.extend_from_slice(&[9;16]);
    let mut outcome=vec![0u8,1,5];outcome.extend_from_slice(&[9;16]);
    outcome.extend_from_slice(&[0,0,0,0,0,0,0,5]);
    c.execute("INSERT INTO command_receipts VALUES(?1,?2,?3,?4,?5,11)",
        params![&[7u8;16][..],scope,&b"k"[..],&[3u8;32][..],outcome]).unwrap();
    c.execute_batch("PRAGMA query_only=ON").unwrap();c
}
fn observe(c:&mut Connection)->Result<(Option<i64>,Snapshot)> {
    capture_checked_connection(c,Limits::fixture(),Some(&intent()))
}
#[test] fn receipt_and_snapshot_share_success_boundary() {
    let mut c=fixture();let (time,first)=observe(&mut c).unwrap();
    assert_eq!(time,Some(11));assert!(c.is_autocommit());
    assert_eq!(first,capture_connection(&mut c,Limits::fixture()).unwrap());
}
#[test] fn bad_fingerprint_refuses_and_releases_transaction() {
    let mut c=fixture();assert!(observe(&mut c).is_ok());
    c.execute_batch("PRAGMA query_only=OFF;UPDATE command_receipts SET fingerprint=zeroblob(32);
        PRAGMA query_only=ON;").unwrap();
    assert!(observe(&mut c).is_err());assert!(c.is_autocommit());
    let fence:i64=c.query_row("PRAGMA query_only",[],|r|r.get(0)).unwrap();assert_eq!(fence,1);
}
#[test] fn duplicate_original_command_refuses() {
    let mut c=fixture();assert!(observe(&mut c).is_ok());
    c.execute_batch("PRAGMA query_only=OFF;INSERT INTO command_receipts
        SELECT * FROM command_receipts;PRAGMA query_only=ON;").unwrap();
    assert!(observe(&mut c).is_err());assert!(c.is_autocommit());
}
#[test] fn scope_key_collision_under_another_command_refuses() {
    let mut c=fixture();assert!(observe(&mut c).is_ok());
    c.execute_batch("PRAGMA query_only=OFF;INSERT INTO command_receipts
        SELECT zeroblob(16),idempotency_scope_bytes,idempotency_key,fingerprint,
        command_outcome,committed_at FROM command_receipts;PRAGMA query_only=ON;").unwrap();
    assert!(observe(&mut c).is_err());assert!(c.is_autocommit());
}
#[test] fn text_command_alias_is_not_hidden_by_blob_filter() {
    let mut c=fixture();assert!(observe(&mut c).is_ok());
    c.execute_batch("PRAGMA query_only=OFF;INSERT INTO command_receipts
        SELECT CAST(command_id AS TEXT),idempotency_scope_bytes,idempotency_key,
        fingerprint,command_outcome,committed_at FROM command_receipts;
        PRAGMA query_only=ON;").unwrap();
    assert!(observe(&mut c).is_err());
}
#[test] fn text_scope_and_key_alias_conflict_is_not_hidden() {
    let mut c=fixture();assert!(observe(&mut c).is_ok());
    c.execute_batch("PRAGMA query_only=OFF;INSERT INTO command_receipts
        SELECT zeroblob(16),CAST(idempotency_scope_bytes AS TEXT),
        CAST(idempotency_key AS TEXT),fingerprint,command_outcome,committed_at
        FROM command_receipts;PRAGMA query_only=ON;").unwrap();
    assert!(observe(&mut c).is_err());
}
#[test] fn real_timestamp_is_not_integer_timestamp() {
    let mut c=fixture();assert!(observe(&mut c).is_ok());
    c.execute_batch("PRAGMA query_only=OFF;UPDATE command_receipts SET committed_at=11.0;
        PRAGMA query_only=ON;").unwrap();assert!(observe(&mut c).is_err());
}
#[test] fn text_payload_is_not_blob_payload() {
    let mut c=fixture();assert!(observe(&mut c).is_ok());
    c.execute_batch("PRAGMA query_only=OFF;UPDATE command_receipts
        SET command_outcome=CAST(command_outcome AS TEXT);PRAGMA query_only=ON;").unwrap();
    assert!(observe(&mut c).is_err());
}
#[test] fn absent_original_receipt_refuses() {
    let mut c=fixture();assert!(observe(&mut c).is_ok());
    c.execute_batch("PRAGMA query_only=OFF;DELETE FROM command_receipts;
        PRAGMA query_only=ON;").unwrap();assert!(observe(&mut c).is_err());
}
#[test] fn missing_receipt_table_refuses_even_after_snapshot_succeeds() {
    let mut c=fixture();assert!(observe(&mut c).is_ok());
    c.execute_batch("PRAGMA query_only=OFF;DROP TABLE command_receipts;
        PRAGMA query_only=ON;").unwrap();assert!(observe(&mut c).is_err());
    assert!(c.is_autocommit());
}
#[test] fn receipt_wrapper_preserves_existing_transaction() {
    let mut c=fixture();c.execute_batch("BEGIN").unwrap();
    assert!(observe(&mut c).is_err());assert!(!c.is_autocommit());
    c.execute_batch("ROLLBACK").unwrap();assert!(observe(&mut c).is_ok());
}
#[test] fn snapshot_budget_refusal_prevents_returning_receipt_success() {
    let mut c=fixture();assert!(observe(&mut c).is_ok());
    let limits=Limits {bytes:1,..Limits::fixture()};
    assert!(capture_checked_connection(&mut c,limits,Some(&intent())).is_err());
    assert!(c.is_autocommit());
}

#[test] fn receipt_view_cannot_impersonate_base_table() {
    let mut c=fixture();assert!(observe(&mut c).is_ok());
    c.execute_batch("PRAGMA query_only=OFF;
        ALTER TABLE command_receipts RENAME TO saved_receipts;
        CREATE VIEW command_receipts AS SELECT * FROM saved_receipts;
        PRAGMA query_only=ON;").unwrap();
    assert!(capture_connection(&mut c,Limits::fixture()).is_ok());
    let count:i64=c.query_row("SELECT COUNT(*) FROM command_receipts",[],|r|r.get(0)).unwrap();
    assert_eq!(count,1); // conforming view is readable, not missing/malformed SQL
    assert!(observe(&mut c).is_err());assert!(c.is_autocommit());
}

#[test] fn view_with_temp_metadata_spoof_is_refused() {
    let mut c=fixture();assert!(observe(&mut c).is_ok());
    c.execute_batch("PRAGMA query_only=OFF;
        ALTER TABLE command_receipts RENAME TO saved_receipts;
        CREATE VIEW command_receipts AS SELECT * FROM saved_receipts;
        CREATE TEMP TABLE pragma_table_list(schema,name,type,wr);
        INSERT INTO temp.pragma_table_list VALUES
          ('main','history','table',0),('main','saved_receipts','table',0),
          ('main','command_receipts','table',0);
        PRAGMA query_only=ON;").unwrap();
    let kind:String=c.query_row("SELECT type FROM temp.pragma_table_list
        WHERE name='command_receipts'",[],|r|r.get(0)).unwrap();assert_eq!(kind,"table");
    let count:i64=c.query_row("SELECT COUNT(*) FROM main.command_receipts",[],|r|r.get(0)).unwrap();
    assert_eq!(count,1);assert!(observe(&mut c).is_err());assert!(c.is_autocommit());
}
#[test] fn view_with_main_metadata_spoof_is_refused() {
    let mut c=fixture();assert!(observe(&mut c).is_ok());
    c.execute_batch("PRAGMA query_only=OFF;
        ALTER TABLE command_receipts RENAME TO saved_receipts;
        CREATE VIEW command_receipts AS SELECT * FROM saved_receipts;
        CREATE TABLE pragma_table_list(schema,name,type,wr);
        INSERT INTO main.pragma_table_list VALUES
          ('main','history','table',0),('main','saved_receipts','table',0),
          ('main','command_receipts','table',0),('main','pragma_table_list','table',0);
        PRAGMA query_only=ON;").unwrap();
    let count:i64=c.query_row("SELECT COUNT(*) FROM main.command_receipts",[],|r|r.get(0)).unwrap();
    assert_eq!(count,1);assert!(observe(&mut c).is_err());assert!(c.is_autocommit());
}
