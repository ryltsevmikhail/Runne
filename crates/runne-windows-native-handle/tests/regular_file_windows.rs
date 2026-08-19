#![cfg(windows)]

use runne_windows_native_handle::{
    inspect_regular_file, move_regular_file_no_replace_write_through, sync_regular_file,
};

#[test]
fn regular_file_identity_sync_and_no_replace_move_are_native() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let temporary = directory.path().join("temporary.sqlite3");
    let final_path = directory.path().join("final.sqlite3");
    std::fs::write(&temporary, b"private snapshot").expect("temporary file");
    let source = inspect_regular_file(&temporary).expect("source inspection");
    assert_eq!(source.link_count(), 1);
    sync_regular_file(&temporary, source.id()).expect("source sync");
    move_regular_file_no_replace_write_through(&temporary, &final_path, source.id())
        .expect("write-through move");
    let final_snapshot = inspect_regular_file(&final_path).expect("final inspection");
    assert_eq!(final_snapshot.id(), source.id());
    assert_eq!(final_snapshot.link_count(), 1);
}
