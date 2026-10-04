use super::*;
use runne_application::ports::EventStore;
use runne_runtime::provider_execution::ProviderTerminalOutboxApplication;

impl DaemonCanonicalProviderService {
    /// Settles only the exact cancellation-scan candidate after ordinary
    /// no-effect completion found an existing claim. This runs independently
    /// of the foreground execution future and never probes an uncertain effect.
    pub(crate) async fn settle_claimed_cancellation(
        &self,
        taskrun_id: runne_domain::id::TaskRunId,
        cancellation_version: u64,
    ) -> Result<bool, RuntimeProviderExecutionError> {
        let runtime_store = Arc::clone(&self.runtime_store);
        let profile = Arc::clone(&self.profile);
        let keyring = Arc::clone(&self.keyring);
        let prohibited = Arc::clone(&self.prohibited_content);
        let scanner_store = Arc::clone(&self.scanner_store);
        let tail_store = Arc::clone(&self.tail_store);
        let store = self.conversation_store.clone();
        let service = Arc::clone(&self.conversation_service);
        let application =
            ConversationProviderTerminalApplication::new(store.clone(), Arc::clone(&service));
        let authority = self.runtime_authority_id;
        let generation = self.database_generation;
        tokio::task::spawn_blocking(move || {
            let matcher = ProhibitedContentCredentialMatcher::new(prohibited.as_ref());
            let redaction = ProviderEventRedactionBoundary::new(
                tail_store.as_ref(), scanner_store.as_ref(), &matcher,
            );
            let execution = RuntimeProviderExecution::new(
                keyring.as_ref(), runtime_store.as_ref(), profile.as_ref(),
                prohibited.as_ref(), &redaction,
            );
            execution.preflight_existing_active_key(authority, generation)?;
            let stream = store.load_task_run(taskrun_id)
                .map_err(|_| RuntimeProviderExecutionError::ApplicationUnavailable)?;
            if stream.current_version != cancellation_version {
                return Ok(false);
            }
            let pending = execution.recover_pending_terminal_outputs()?;
            let mut exact = pending.into_iter().filter(|item| item.record().taskrun_id == taskrun_id);
            if let Some(output) = exact.next() {
                if exact.next().is_some() { return Err(RuntimeProviderExecutionError::ApplicationConflict); }
                let record = output.record();
                let receipt_digest = application.complete_provider_terminal_cancellation(record, output.output())
                    .map_err(|error| match error {
                        runne_runtime::provider_execution::ProviderTerminalApplicationError::Unavailable => RuntimeProviderExecutionError::ApplicationUnavailable,
                        runne_runtime::provider_execution::ProviderTerminalApplicationError::Deferred => RuntimeProviderExecutionError::ApplicationConflict,
                        runne_runtime::provider_execution::ProviderTerminalApplicationError::Conflict => RuntimeProviderExecutionError::ApplicationConflict,
                    })?;
                if receipt_digest == [0; 32] { return Err(RuntimeProviderExecutionError::ApplicationConflict); }
                execution.acknowledge_terminal_output(record.outbox_id, receipt_digest)?;
                return Ok(true);
            }
            super::provider_failure_recovery::recover_exact_cancelled_taskrun(
                &execution, &redaction, &store, service.as_ref(), taskrun_id, cancellation_version,
            ).map_err(|_| RuntimeProviderExecutionError::ApplicationConflict)
        })
        .await
        .map_err(|_| RuntimeProviderExecutionError::ApplicationUnavailable)?
    }

    pub(super) async fn recover_pending(&self) -> Result<(), DaemonError> {
        let runtime_store = Arc::clone(&self.runtime_store);
        let profile = Arc::clone(&self.profile);
        let keyring = Arc::clone(&self.keyring);
        let prohibited = Arc::clone(&self.prohibited_content);
        let scanner_store = Arc::clone(&self.scanner_store);
        let tail_store = Arc::clone(&self.tail_store);
        let registry = Arc::clone(&self.recovery_registry);
        let failure_store = self.conversation_store.clone();
        let failure_service = Arc::clone(&self.conversation_service);
        let application = ConversationProviderTerminalApplication::new(
            self.conversation_store.clone(),
            Arc::clone(&self.conversation_service),
        );
        let authority = self.runtime_authority_id;
        let generation = self.database_generation;
        tokio::task::spawn_blocking(move || {
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
            execution.preflight_existing_active_key(authority, generation)?;
            execution.apply_pending_terminal_outputs(&application, registry.as_ref())?;
            execution
                .apply_pending_terminal_cancellation_outputs(&application, registry.as_ref())?;
            super::provider_failure_recovery::recover_settled_failures(
                &execution,
                &redaction,
                &failure_store,
                failure_service.as_ref(),
            )
            .map_err(|_| RuntimeProviderExecutionError::ApplicationConflict)?;
            Ok::<(), RuntimeProviderExecutionError>(())
        })
        .await
        .map_err(|_| DaemonError::Bootstrap("provider recovery unavailable".into()))?
        .map(|_| ())
        .map_err(|_| DaemonError::Bootstrap("provider recovery unavailable".into()))
    }
}
