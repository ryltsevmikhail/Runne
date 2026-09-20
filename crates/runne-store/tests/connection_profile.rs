use std::path::PathBuf;

use runne_store::schema::{
    ConnectionMode, ManagedConnection, ManagedConnectionAuthority, PublicationPermit, Readiness,
    apply_migrations, open_managed_connection, publication_from_managed, readiness_from_managed,
};
// The validated-reopen API rejects a runtime identity only through the
// unix handle movement control today.
#[cfg(unix)]
use runne_store::schema::reopen_managed_connection_validated;
use rusqlite::{Connection, Result as SqliteResult};

struct Database {
    _root: tempfile::TempDir,
    path: PathBuf,
}

impl Database {
    fn new(name: &str) -> Self {
        let root = tempfile::Builder::new().prefix(name).tempdir().unwrap();
        let daemon = root.path().join("runne-daemon");
        std::fs::create_dir(&daemon).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self {
            _root: root,
            path: daemon.join("event-log.sqlite"),
        }
    }
}

fn assert_profile(connection: &ManagedConnection, query_only: i64) {
    let journal_mode: String = connection
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    let synchronous: i64 = connection
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .unwrap();
    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .unwrap();
    let busy_timeout: i64 = connection
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .unwrap();
    let actual_query_only: i64 = connection
        .query_row("PRAGMA query_only", [], |row| row.get(0))
        .unwrap();

    assert_eq!(journal_mode, "wal");
    assert_eq!(synchronous, 2);
    assert_eq!(foreign_keys, 1);
    assert_eq!(busy_timeout, 5_000);
    assert_eq!(actual_query_only, query_only);
    #[cfg(target_os = "macos")]
    assert_eq!(
        connection
            .query_row("PRAGMA fullfsync", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
}

trait AmbiguousIfManaged<A> {
    fn assert_not_managed() {}
}

impl<T: ?Sized> AmbiguousIfManaged<()> for T {}
impl<T: ?Sized + ManagedConnectionAuthority> AmbiguousIfManaged<u8> for T {}

fn assert_raw_connection_is_not_managed() {
    let _ = <Connection as AmbiguousIfManaged<_>>::assert_not_managed;
}

#[test]
fn writer_reader_and_reopen_read_back_required_pragmas() {
    let database = Database::new("connection-profile");
    let writer = open_managed_connection(&database.path, ConnectionMode::Writer).unwrap();
    apply_migrations(&writer).unwrap();
    assert_profile(&writer, 0);
    readiness_from_managed(&writer).unwrap();
    publication_from_managed(&writer).unwrap();

    let reader = open_managed_connection(&database.path, ConnectionMode::Reader).unwrap();
    assert_profile(&reader, 1);
    readiness_from_managed(&reader).unwrap();
    publication_from_managed(&reader).unwrap();
    drop(reader);
    drop(writer);

    #[cfg(unix)]
    {
        let reopened = reopen_managed_connection_validated(
            &database.path,
            ConnectionMode::ValidatedReopen,
            |_| Ok(()),
        )
        .unwrap();
        assert_profile(&reopened, 0);
        readiness_from_managed(&reopened).unwrap();
        publication_from_managed(&reopened).unwrap();
    }
}

#[test]
fn raw_open_without_profile_blocks_readiness() {
    assert_raw_connection_is_not_managed();
    let raw = Connection::open_in_memory().unwrap();
    apply_migrations(&raw).unwrap();
    let query_only: i64 = raw
        .query_row("PRAGMA query_only", [], |row| row.get(0))
        .unwrap();
    assert_eq!(query_only, 0);

    let _: fn(&ManagedConnection) -> SqliteResult<Readiness> = readiness_from_managed;
    let _: fn(&ManagedConnection) -> SqliteResult<PublicationPermit> = publication_from_managed;
}

#[test]
fn raw_connection_with_identical_manual_pragmas_cannot_forge_managed_capability() {
    assert_raw_connection_is_not_managed();
    let database = Database::new("manual-profile");
    let raw = Connection::open(&database.path).unwrap();
    raw.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;",
    )
    .unwrap();
    assert_eq!(
        raw.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "wal"
    );
    assert_eq!(
        raw.query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        2
    );
    assert_eq!(
        raw.query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        raw.query_row("PRAGMA busy_timeout", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        5_000
    );
}

#[test]
#[cfg(target_os = "macos")]
fn unsupported_or_ignored_fullfsync_blocks_macos_readiness() {
    let database = Database::new("fullfsync-profile");
    let connection = open_managed_connection(&database.path, ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
    connection.execute_batch("PRAGMA fullfsync = OFF").unwrap();
    assert!(readiness_from_managed(&connection).is_err());
    assert!(publication_from_managed(&connection).is_err());
}

#[test]
#[cfg(not(target_os = "macos"))]
fn unsupported_or_ignored_fullfsync_blocks_macos_readiness() {}

#[test]
fn managed_reader_remains_query_only() {
    let database = Database::new("managed-reader");
    let writer = open_managed_connection(&database.path, ConnectionMode::Writer).unwrap();
    apply_migrations(&writer).unwrap();
    let reader = open_managed_connection(&database.path, ConnectionMode::Reader).unwrap();

    assert!(
        reader
            .execute_batch("CREATE TABLE forbidden (id INTEGER)")
            .is_err()
    );
    assert_profile(&reader, 1);
}

#[cfg(unix)]
#[test]
fn validated_reopen_runs_runtime_identity_closure_before_profile() {
    let database = Database::new("validated-order");
    let writer = open_managed_connection(&database.path, ConnectionMode::Writer).unwrap();
    apply_migrations(&writer).unwrap();
    drop(writer);

    let reopened = reopen_managed_connection_validated(
        &database.path,
        ConnectionMode::ValidatedReopen,
        |connection| {
            let query_only: i64 =
                connection.query_row("PRAGMA query_only", [], |row| row.get(0))?;
            assert_eq!(query_only, 1);
            Ok(())
        },
    )
    .unwrap();
    assert_profile(&reopened, 0);
}
