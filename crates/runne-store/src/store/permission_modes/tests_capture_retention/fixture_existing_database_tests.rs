//! New source regressions; NOTRUN. These are in-process DB adapter tests only.
use super::*;

#[test]
fn controller_anchor_precedes_reopen_and_identity_is_preserved() {
    let root = tempfile::tempdir().unwrap();
    let original = ControllerDatabase::create(&root).unwrap();
    let reference = original.reference();
    original.anchor().verify().unwrap();
    let (path, writer, reader) = reference.open().unwrap();
    assert_eq!(path, reference.path);
    original.anchor().verify_reader(&reader).unwrap();
    assert_eq!(schema::read_authority_id(&writer).unwrap(), Some(reference.authority));
    assert_eq!(schema::read_event_log_lineage_id(&reader).unwrap(), Some(reference.lineage));
    let query_only: i64 = reader.pragma_query_value(None, "query_only", |r| r.get(0)).unwrap();
    assert_eq!(query_only, 1);
    assert_eq!(writer.pragma_query_value(None, "query_only", |r| r.get::<_, i64>(0)).unwrap(), 0);
    drop(reader); drop(writer);
    original.anchor().verify().unwrap();
}

#[test]
fn wrong_authority_or_lineage_refuses_without_replacing_ids() {
    let root = tempfile::tempdir().unwrap();
    let original = ControllerDatabase::create(&root).unwrap();
    let reference = original.reference();
    for authority in [true, false] {
        let mut wrong = reference;
        if authority { wrong.authority = uuid::Uuid::now_v7().into_bytes(); }
        else { wrong.lineage = EventLogLineageId::from_bytes(uuid::Uuid::now_v7().into_bytes()); }
        assert!(wrong.open().is_err());
        let (_, writer, reader) = reference.open().unwrap();
        original.anchor().verify_reader(&reader).unwrap();
        assert_eq!(schema::read_authority_id(&writer).unwrap(), Some(reference.authority));
        assert_eq!(schema::read_event_log_lineage_id(&writer).unwrap(), Some(reference.lineage));
    }
}

#[test]
fn controller_root_is_exclusive_not_an_idempotent_bootstrap() {
    let root = tempfile::tempdir().unwrap();
    let original = ControllerDatabase::create(&root).unwrap();
    assert!(ControllerDatabase::create(&root).is_err());
    let (_, _writer, reader) = original.reference().open().unwrap();
    original.anchor().verify_reader(&reader).unwrap();
}

#[test]
fn replacement_with_copied_identity_rows_is_not_original_inode() {
    let first_root = tempfile::tempdir().unwrap();
    let original = ControllerDatabase::create(&first_root).unwrap();
    let second_root = tempfile::tempdir().unwrap();
    let different = ControllerDatabase::create(&second_root).unwrap();
    let a = original.reference(); let b = different.reference();
    let (_, writer, reader) = b.open().unwrap();
    writer.execute("UPDATE _authority SET authority_id=?1 WHERE id=1", [a.authority.as_slice()]).unwrap();
    writer.execute("UPDATE _daemon_info SET value=?1 WHERE key='event_log_lineage_id'", [a.lineage.to_string()]).unwrap();
    let (_, _replacement_writer, replacement_reader) = ExistingDatabase {
        path: b.path, authority: a.authority, lineage: a.lineage,
    }.open().unwrap();
    assert!(original.anchor().verify_reader(&replacement_reader).is_err());
    drop(reader);
}
