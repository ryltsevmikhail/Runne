//! Validated ownerless control recovery, never the original uncertain task.
use crate::{
    schema::{self, ConnectionMode, ManagedConnection},
    store::StoreTransaction,
};
use runne_application::ports::{ExecutionNodeId, RuntimeAuthorityId};
use runne_domain::id::EventLogLineageId;
use std::{path::Path, sync::Arc};

pub(super) fn connection(
    db: &Path,
    authority: [u8; 16],
    lineage: EventLogLineageId,
    mode: ConnectionMode,
) -> ManagedConnection {
    schema::reopen_managed_connection_validated(db, mode, |c| {
        if schema::read_authority_id(c)? != Some(authority)
            || schema::read_event_log_lineage_id(c)? != Some(lineage)
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        Ok(())
    })
    .unwrap()
}
pub(super) fn store(
    db: &Path,
    authority: [u8; 16],
    lineage: EventLogLineageId,
    old_epoch: u64,
) -> (StoreTransaction, ExecutionNodeId, u64) {
    let writer = connection(db, authority, lineage, ConnectionMode::ValidatedReopen);
    let epoch = schema::next_launch_generation(&writer).unwrap();
    assert!(epoch > old_epoch);
    crate::execution_node::register_local_linux_node(
        &writer,
        authority,
        epoch,
        crate::execution_node::LinuxNodeDescriptor { capacity: 1 },
        30,
    )
    .unwrap();
    crate::execution_node::heartbeat_local_linux_node(&writer, authority, epoch, 30).unwrap();
    let reader = connection(db, authority, lineage, ConnectionMode::Reader);
    let store = StoreTransaction::open_with_connections(
        db.to_str().unwrap(),
        writer,
        reader,
        RuntimeAuthorityId(hex::encode(authority)),
        Arc::new(runne_security::SecretBroker::new().prohibited_content_guard()),
    )
    .unwrap();
    (
        store,
        ExecutionNodeId(uuid::Uuid::from_bytes(authority).to_string()),
        epoch,
    )
}
