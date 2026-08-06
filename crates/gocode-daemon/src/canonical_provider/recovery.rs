use super::*;

impl DaemonCanonicalOpenAiService {
    pub(super) async fn recover_pending(&self) -> Result<(), DaemonError> {
        let runtime_store = Arc::clone(&self.runtime_store);
        let profile = Arc::clone(&self.profile);
        let keyring = Arc::clone(&self.keyring);
        let prohibited = Arc::clone(&self.prohibited_content);
        let registry = Arc::clone(&self.recovery_registry);
        let application = ConversationProviderTerminalApplication::new(
            self.conversation_store.clone(),
            Arc::clone(&self.conversation_service),
        );
        let authority = self.runtime_authority_id;
        let generation = self.database_generation;
        tokio::task::spawn_blocking(move || {
            let execution = RuntimeProviderExecution::new(
                keyring.as_ref(),
                runtime_store.as_ref(),
                profile.as_ref(),
                prohibited.as_ref(),
            );
            execution.preflight_existing_active_key(authority, generation)?;
            execution.apply_pending_terminal_outputs(&application, registry.as_ref())
        })
        .await
        .map_err(|_| DaemonError::Bootstrap("provider recovery unavailable".into()))?
        .map(|_| ())
        .map_err(|_| DaemonError::Bootstrap("provider recovery unavailable".into()))
    }
}
