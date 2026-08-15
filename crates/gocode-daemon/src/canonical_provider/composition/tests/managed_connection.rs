use gocode_domain::id::EventLogLineageId;
use gocode_store::schema::{
    ConnectionMode, ManagedConnection, read_authority_id, read_event_log_lineage_id,
    reopen_managed_connection_validated,
};

pub(super) fn managed_test_connection(
    path: &str,
    authority: [u8; 16],
    lineage: EventLogLineageId,
    mode: ConnectionMode,
) -> ManagedConnection {
    reopen_managed_connection_validated(std::path::Path::new(path), mode, |connection| {
        if read_authority_id(connection)? == Some(authority)
            && read_event_log_lineage_id(connection)? == Some(lineage)
        {
            Ok(())
        } else {
            Err(rusqlite::Error::InvalidQuery)
        }
    })
    .unwrap()
}
