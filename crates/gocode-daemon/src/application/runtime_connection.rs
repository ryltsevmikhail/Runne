use std::path::Path;

use gocode_domain::id::EventLogLineageId;
use gocode_store::schema::{
    ConnectionMode, ManagedConnection, publication_from_managed, read_authority_id,
    read_event_log_lineage_id, readiness_from_managed, reopen_managed_connection_validated,
};

use super::*;

pub(super) fn open_runtime_connection(
    db_path: &str,
    mode: ConnectionMode,
    authority_id: [u8; 16],
    lineage_id: EventLogLineageId,
    purpose: &str,
) -> Result<ManagedConnection, DaemonError> {
    let connection = reopen_managed_connection_validated(Path::new(db_path), mode, |connection| {
        validate_runtime_identity(connection, authority_id, lineage_id)
    })
    .map_err(|error| DaemonError::Bootstrap(format!("open {purpose}: {error}")))?;
    readiness_from_managed(&connection)
        .and_then(|_| publication_from_managed(&connection).map(|_| ()))
        .map_err(|error| DaemonError::Bootstrap(format!("verify {purpose}: {error}")))?;
    Ok(connection)
}

fn validate_runtime_identity(
    connection: &rusqlite::Connection,
    authority_id: [u8; 16],
    lineage_id: EventLogLineageId,
) -> rusqlite::Result<()> {
    if read_authority_id(connection)? == Some(authority_id)
        && read_event_log_lineage_id(connection)? == Some(lineage_id)
    {
        Ok(())
    } else {
        Err(rusqlite::Error::InvalidQuery)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use gocode_store::schema::{
        apply_migrations, ensure_authority_id, ensure_exact_event_log_lineage_id,
        open_managed_connection,
    };

    #[test]
    fn managed_runtime_reopen_rejects_authority_or_lineage_mismatch() {
        let root = tempfile::tempdir().unwrap();
        let daemon = root.path().join("gocode-daemon");
        std::fs::create_dir(&daemon).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = daemon.join("event-log.sqlite");
        let authority = uuid_v7(1);
        let lineage = EventLogLineageId::from_bytes(uuid_v7(2));
        let connection = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
        apply_migrations(&connection).unwrap();
        ensure_authority_id(&connection, &authority).unwrap();
        ensure_exact_event_log_lineage_id(&connection, lineage).unwrap();
        drop(connection);

        drop(
            open_runtime_connection(
                path.to_str().unwrap(),
                ConnectionMode::ValidatedReopen,
                authority,
                lineage,
                "test runtime",
            )
            .unwrap(),
        );
        assert!(
            open_runtime_connection(
                path.to_str().unwrap(),
                ConnectionMode::ValidatedReopen,
                uuid_v7(3),
                lineage,
                "wrong authority",
            )
            .is_err()
        );
        assert!(
            open_runtime_connection(
                path.to_str().unwrap(),
                ConnectionMode::ValidatedReopen,
                authority,
                EventLogLineageId::from_bytes(uuid_v7(4)),
                "wrong lineage",
            )
            .is_err()
        );
    }

    fn uuid_v7(last: u8) -> [u8; 16] {
        [
            0x01, 0x8f, 0x2e, 0x3a, 0x70, 0x00, 0x70, 0x00, 0x80, 0, 0, 0, 0, 0, 0, last,
        ]
    }
}
