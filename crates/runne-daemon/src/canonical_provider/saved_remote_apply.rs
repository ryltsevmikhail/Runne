use super::*;
impl DaemonCanonicalProviderService {
    pub(super) async fn apply_saved_remote_terminal(
        &self,
        attempt_id: runne_provider::DispatchAttemptId,
        profile: Arc<SharedTextProviderProfile>,
        cancellation_owner: bool,
        attempt_guard: Arc<super::saved_remote_gate::SavedRemoteAttemptGuard>,
    ) -> Result<bool, DaemonError> {
        let Some(permit) = self.saved_remote_gate.reserve_candidate() else {
            return Ok(false);
        };
        let runtime_store = Arc::clone(&self.runtime_store);
        let keyring = Arc::clone(&self.keyring);
        let prohibited = Arc::clone(&self.prohibited_content);
        let scanner_store = Arc::clone(&self.scanner_store);
        let tail_store = Arc::clone(&self.tail_store);
        let conversation_store = self.conversation_store.clone();
        let conversation_service = Arc::clone(&self.conversation_service);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _attempt_guard = attempt_guard;
            let matcher = ProhibitedContentCredentialMatcher::new(prohibited.as_ref());
            let redaction = ProviderEventRedactionBoundary::new(
                tail_store.as_ref(),
                scanner_store.as_ref(),
                &matcher,
            );
            let execution = RuntimeProviderExecution::new(
                keyring.as_ref(),
                runtime_store.as_ref(),
                profile.as_ref(),
                prohibited.as_ref(),
                &redaction,
            );
            let application = ConversationProviderTerminalApplication::new(
                conversation_store,
                conversation_service,
            );
            let output_applied = if cancellation_owner {
                execution.apply_terminal_cancellation_output_for_attempt(attempt_id, &application)
            } else {
                execution.apply_terminal_output_for_attempt(attempt_id, &application)
            }?;
            if output_applied {
                Ok(true)
            } else {
                execution.apply_remote_terminal_without_output(attempt_id, &application)
            }
        })
        .await
        .map_err(|_| DaemonError::Bootstrap("provider terminal application unavailable".into()))?
        .map_err(|_| DaemonError::Bootstrap("provider terminal application unavailable".into()))
    }
}
