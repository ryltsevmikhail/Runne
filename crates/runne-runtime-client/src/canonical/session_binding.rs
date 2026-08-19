impl RuntimeSessionInfo {
    fn replay_binding(&self) -> Option<runne_api::RuntimeSessionBinding> {
        let authority_id = uuid::Uuid::parse_str(&self.authority_id).ok()?.into_bytes();
        let lineage = self.event_log_lineage_id.parse().ok()?;
        let daemon = runne_api::DaemonInstanceId::from_bytes(
            uuid::Uuid::parse_str(&self.daemon_instance_id)
                .ok()?
                .into_bytes(),
        );
        let schema_hash: [u8; 32] = hex::decode(&self.schema_hash).ok()?.try_into().ok()?;
        let capabilities: [u8; 32] = hex::decode(&self.capability_digest).ok()?.try_into().ok()?;
        let certificate: [u8; 32] = hex::decode(&self.certificate_sha256)
            .ok()?
            .try_into()
            .ok()?;
        let session_id: [u8; 16] = hex::decode(&self.session_id).ok()?.try_into().ok()?;
        let stable = runne_api::StableRuntimeBinding::new(
            authority_id,
            runne_api::ApiPrincipalId::new(self.principal_id.clone()).ok()?,
            lineage,
            self.profile_id.clone(),
            schema_hash,
            capabilities,
        )
        .ok()?;
        runne_api::RuntimeSessionBinding::new_with_sensitivity_label(
            stable,
            daemon,
            self.launch_generation,
            session_id,
            self.authorization_epoch,
            &self.sensitivity_ceiling,
            certificate,
        )
        .ok()
    }
}
