//! Guest-only constructor integration; no real application or native effect.
//! Execute only under a separately reviewed bounded disposable Linux packet.
use super::*;

#[test]
fn guest_fixture_keeps_controller_original_database_and_authority() {
    let root = tempfile::tempdir().unwrap();
    let controller = ControllerDatabase::create(&root).unwrap();
    let reference = controller.reference();
    controller.anchor().verify().unwrap();
    let worker_root = tempfile::tempdir_in(root.path()).unwrap();
    let fixture = super::super::Fixture::with_root_and_existing_database(worker_root, reference);
    assert_eq!(fixture.scope.runtime_authority_id.0, hex::encode(reference.authority));
    {
        let writer = fixture.store.inner.writer.lock().unwrap();
        assert_eq!(schema::read_authority_id(&writer).unwrap(), Some(reference.authority));
        assert_eq!(schema::read_event_log_lineage_id(&writer).unwrap(), Some(reference.lineage));
    }
    {
        let reader = fixture.store.inner.reader.lock().unwrap();
        controller.anchor().verify_reader(&reader).unwrap();
        assert_eq!(schema::read_authority_id(&reader).unwrap(), Some(reference.authority));
    }
    drop(fixture);
    // Its separate workspace/trust roots may close; C's original DB must remain.
    controller.anchor().verify().unwrap();
    let (_, _writer, reader) = reference.open().unwrap();
    controller.anchor().verify_reader(&reader).unwrap();
}
