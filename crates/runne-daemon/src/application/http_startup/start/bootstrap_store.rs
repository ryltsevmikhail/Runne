use super::*;

pub(super) fn open(
    config: &ConfigurationSnapshot,
    authority: [u8; 16],
    lineage: runne_domain::id::EventLogLineageId,
) -> Result<Arc<SqliteBootstrapReservationStore>, DaemonError> {
    let connection = open_runtime_connection(
        &config.db_path,
        runne_store::schema::ConnectionMode::ValidatedReopen,
        authority,
        lineage,
        "bootstrap reservation store",
    )?;
    Ok(Arc::new(SqliteBootstrapReservationStore::new(connection)))
}
