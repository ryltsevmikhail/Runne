use runne_domain::id::EventLogLineageId;
use runne_store::schema::{
    ConnectionMode, ManagedConnection, read_authority_id, read_event_log_lineage_id,
    reopen_managed_connection_validated,
};

pub(super) fn managed_test_connection(
    path: &str,
    authority: [u8; 16],
    lineage: EventLogLineageId,
    mode: ConnectionMode,
) -> ManagedConnection {
    try_managed_test_connection(path, authority, lineage, mode).unwrap()
}

pub(super) fn try_managed_test_connection(
    path: &str,
    authority: [u8; 16],
    lineage: EventLogLineageId,
    mode: ConnectionMode,
) -> rusqlite::Result<ManagedConnection> {
    reopen_managed_connection_validated(std::path::Path::new(path), mode, |connection| {
        if read_authority_id(connection)? == Some(authority)
            && read_event_log_lineage_id(connection)? == Some(lineage)
        {
            Ok(())
        } else {
            Err(rusqlite::Error::InvalidQuery)
        }
    })
}
