//! Windows regressions for the audited `SQLite` handle bridge.
//!
//! `SQLITE_FCNTL_HAS_MOVED` is implemented by the bundled engine's
//! `unixFileControl` only; the win32 VFS answers `SQLITE_NOTFOUND`. The first
//! test pins that fact so the fail-closed guard below never silently degrades
//! into the opposite mistake of treating "unsupported" as "not moved".

use super::*;

fn disk_connection() -> (std::path::PathBuf, rusqlite::Connection) {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sqlite-win-{}-{stamp}", std::process::id()));
    std::fs::create_dir(&root).expect("own temporary directory");
    let path = root.join("database.sqlite");
    let connection = rusqlite::Connection::open(&path).expect("disk database");
    (root, connection)
}

#[test]
fn has_moved_file_control_stays_unix_only_on_the_pinned_engine() {
    let (_root, connection) = disk_connection();
    connection
        .pragma_update(None, "journal_mode", "wal")
        .expect("wal mode");
    let mut moved = 1_i32;
    // SAFETY: SQLite writes one i32 during this synchronous call.
    let status = unsafe {
        rusqlite::ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            rusqlite::ffi::SQLITE_FCNTL_HAS_MOVED,
            std::ptr::from_mut(&mut moved).cast(),
        )
    };
    // SAFETY: checked non-null and SQLite owns the NUL-terminated strings.
    let version =
        unsafe { std::ffi::CStr::from_ptr(rusqlite::ffi::sqlite3_libversion()) }.to_string_lossy();
    let source =
        unsafe { std::ffi::CStr::from_ptr(rusqlite::ffi::sqlite3_sourceid()) }.to_string_lossy();
    assert_eq!(
        status,
        rusqlite::ffi::SQLITE_NOTFOUND,
        "SQLite {version} ({source}): win32 VFS must keep HAS_MOVED unsupported",
    );
}

#[test]
fn opened_main_identity_matches_the_path_identity_of_the_disk_file() {
    let (root, connection) = disk_connection();
    connection
        .pragma_update(None, "journal_mode", "wal")
        .expect("wal mode");
    connection
        .execute_batch("CREATE TABLE t(v); INSERT INTO t VALUES (1);")
        .expect("write");
    let opened = opened_database_identity(&connection).expect("opened main identity");
    let by_path = path_database_identity(&root.join("database.sqlite")).expect("path identity");
    assert_eq!(opened, by_path);
    let wal = root.join("database.sqlite-wal");
    assert!(wal.exists());
    let journal = opened_journal_identity(&connection).expect("journal identity");
    let wal_by_path = path_database_identity(&wal).expect("wal path identity");
    assert_eq!(journal, Some(wal_by_path));
}

#[test]
fn opened_identity_rejects_databases_without_a_win32_handle() {
    let connection = rusqlite::Connection::open_in_memory().expect("memory database");
    assert_eq!(opened_database_identity(&connection), Err(IdentityError));
}

#[test]
fn retained_identity_survives_rename_and_rejects_replacement() {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!("sqlite-fd-win-{}-{stamp}", std::process::id()));
    std::fs::create_dir(&root).expect("own temporary directory");
    let path = root.join("database");
    let file = File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    let captured = file_database_identity(&file).expect("retained file identity");
    assert_eq!(path_database_identity(&path), Ok(captured));
    let retained = root.join("retained");
    std::fs::rename(&path, &retained).unwrap();
    let replacement = File::options()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    assert_eq!(file_database_identity(&file), Ok(captured));
    assert_ne!(file_database_identity(&replacement), Ok(captured));
    assert_ne!(path_database_identity(&path), Ok(captured));
    // Opening a directory on Windows requires FILE_FLAG_BACKUP_SEMANTICS.
    let directory = {
        use std::os::windows::fs::OpenOptionsExt as _;
        File::options()
            .read(true)
            .custom_flags(0x0200_0000)
            .open(&root)
            .unwrap()
    };
    assert_eq!(file_database_identity(&directory), Err(IdentityError));
    drop(directory);
    drop((file, replacement));
    std::fs::remove_dir_all(root).unwrap();
}
