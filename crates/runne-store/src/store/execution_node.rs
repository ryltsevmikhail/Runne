use super::super::StoreTransaction;
use crate::execution_node::{LinuxNodeDescriptor, NodeRegistryError, RegisteredLinuxNode};

impl StoreTransaction {
    /// Register this daemon epoch through the authoritative SQLite writer.
    pub fn register_local_linux_node(
        &self,
        node_id: [u8; 16],
        launch_generation: u64,
        descriptor: LinuxNodeDescriptor,
        ttl_seconds: u32,
    ) -> Result<RegisteredLinuxNode, NodeRegistryError> {
        let connection = self
            .inner
            .writer
            .lock()
            .map_err(|_| NodeRegistryError::Storage)?;
        crate::execution_node::register_local_linux_node(
            &connection,
            node_id,
            launch_generation,
            descriptor,
            ttl_seconds,
        )
    }

    /// Refresh the current daemon epoch through the authoritative SQLite writer.
    pub fn heartbeat_local_linux_node(
        &self,
        node_id: [u8; 16],
        launch_generation: u64,
        ttl_seconds: u32,
    ) -> Result<(), NodeRegistryError> {
        let connection = self
            .inner
            .writer
            .lock()
            .map_err(|_| NodeRegistryError::Storage)?;
        crate::execution_node::heartbeat_local_linux_node(
            &connection,
            node_id,
            launch_generation,
            ttl_seconds,
        )
    }
}
