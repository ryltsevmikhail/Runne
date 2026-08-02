impl ReplayStore {
   async fn retention_manifest_impl(
        &self,
        lineage_id: &EventLogLineageId,
        server_secret: &[u8; 32],
    ) -> Result<RetentionManifest, ReplayError> {
        let conn = Arc::clone(&self.conn);
        let lineage_id = *lineage_id;
        let server_secret = *server_secret;
        tokio::task::spawn_blocking(move || {
            let conn = conn
                .lock()
                .map_err(|error| ReplayError::Storage(format!("lock poisoned: {error}")))?;
            let transaction = conn
                .unchecked_transaction()
                .map_err(|error| ReplayError::Storage(format!("retention snapshot: {error}")))?;
            let inventory = retained_inventory(&transaction)?;
            if inventory.interior_gap.is_some() {
                return Err(ReplayError::Integrity(
                    "retained event log contains an interior gap".to_owned(),
                ));
            }
            retention_manifest_for_events(&inventory.events, lineage_id, &server_secret)
        })
        .await
        .map_err(|error| ReplayError::Storage(format!("join error: {error}")))?
    }
}
