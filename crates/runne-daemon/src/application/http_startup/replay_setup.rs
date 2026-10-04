use super::super::DaemonError;
use runne_domain::id::EventLogLineageId;
use runne_store::replay_store::ReplayStore;
use std::sync::Arc;

pub(super) async fn prepare_replay_reader(
    connection: runne_store::schema::ManagedConnection,
    lineage: &EventLogLineageId,
    integrity_key: &crate::replay_key::ReplayIntegrityKey,
) -> Result<
    (
        Arc<dyn runne_application::replay_service::ReplayStorePort>,
        [u8; 32],
    ),
    DaemonError,
> {
    let secret = super::super::http_startup_support::replay_cursor_integrity_secret(integrity_key);
    let store = Arc::new(ReplayStore::new(connection))
        as Arc<dyn runne_application::replay_service::ReplayStorePort>;
    let manifest = store
        .retention_manifest(lineage, &secret)
        .await
        .map_err(|error| {
            DaemonError::Bootstrap(format!("measure retained replay inventory: {error}"))
        })?;
    runne_application::replay_service::validate_replay_reader_capacity(
        &manifest,
        runne_application::replay_service::REPLAY_FRAME_CAPACITY_BYTES,
        runne_application::replay_service::REPLAY_PAGE_CAPACITY_BYTES,
        runne_application::replay_service::REPLAY_ENVELOPE_CURSOR_BINDING_OVERHEAD_BYTES,
    )
    .map_err(|error| DaemonError::Config(error.to_string()))?;
    Ok((store, secret))
}
