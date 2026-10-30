use super::*;
impl ConfigurationSnapshot {
    /// Upgrade scope is deliberately limited to the explicit standalone image pins.
    pub(crate) fn validate_cli_upgrade_from(&self, previous: &Self) -> Result<(), DaemonError> {
        if !self.provider_activation.requires_deepseek_execution()
            || self.linux_cli_credential_host.is_none()
            || previous.linux_cli_credential_host.is_none()
            || self.secondary_profile_catalog.is_some()
            || previous.secondary_profile_catalog.is_some()
            || self.d2_safe_tool_loop_budget.is_some()
            || previous.d2_safe_tool_loop_budget.is_some()
        {
            return Err(DaemonError::Config(
                "unsupported installation upgrade scope".into(),
            ));
        }
        let mut values = canonical_values_map(
            self.schema_version,
            &self.db_path,
            &self.http_bind,
            &self.replay_integrity_key_path,
            self.max_in_flight,
            self.shutdown_timeout_ms,
            self.provider_activation.binding(),
            Some(&self.provider_activation_settings),
            None,
        );
        values.insert(
            "linux_cli_credential_host".into(),
            serde_json::json!(previous.linux_cli_credential_host),
        );
        if compute_digest(&values) != previous.digest {
            return Err(DaemonError::Config(
                "installation upgrade changes runtime policy".into(),
            ));
        }
        Ok(())
    }
}
