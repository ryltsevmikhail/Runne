use super::super::super::*;

impl DaemonCanonicalProviderService {
    #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
    pub(crate) fn recover_d2_final_text(
        &self,
        job: &CanonicalProviderExecutionJob,
        terminal: &super::super::D2ToolTerminalRef,
    ) -> Result<String, CanonicalProviderExecutionError> {
        let profile = self.tool_profile.as_deref().ok_or_else(|| {
            crate::application::exec_taskrun_worker::d2_stage(
                "final_text_tool_profile_unavailable",
            );
            CanonicalProviderExecutionError::Unavailable
        })?;
        // This path authenticates an already committed immutable outbox. Its
        // generation may predate a daemon restart; RuntimeProviderExecution
        // verifies the selector against that exact durable record below.
        if terminal.profile_digest != profile.profile_digest() {
            crate::application::exec_taskrun_worker::d2_stage("final_text_profile_mismatch");
            return Err(CanonicalProviderExecutionError::Conflict);
        }
        let matcher = ProhibitedContentCredentialMatcher::new(self.prohibited_content.as_ref());
        let redaction = ProviderEventRedactionBoundary::new(
            self.tail_store.as_ref(),
            self.scanner_store.as_ref(),
            &matcher,
        );
        let execution = RuntimeProviderExecution::new(
            self.keyring.as_ref(),
            self.runtime_store.as_ref(),
            profile,
            self.prohibited_content.as_ref(),
            &redaction,
        );
        let recovered = execution
            .recover_exact_tool_stop(
                runne_runtime::provider_execution::ProviderToolStopSelector {
                    attempt_id: terminal.attempt_id,
                    taskrun_id: job.started.taskrun_id,
                    conversation_id: job.started.conversation_id,
                    execution_attempt_id: job.started.attempt_id,
                    principal_id: job.context.principal_id.0.clone(),
                    outbox_id: terminal.outbox_id,
                    terminal_sequence: terminal.terminal_sequence,
                    settlement_digest: terminal.settlement_digest,
                    fencing_token: terminal.fencing_token,
                    call_digest_version: terminal.call_digest_version,
                    profile_digest: terminal.profile_digest,
                    runtime_generation: terminal.runtime_generation,
                },
            )
            .map_err(|error| {
                crate::application::exec_taskrun_worker::d2_stage(match error {
                    runne_runtime::provider_execution::RuntimeProviderExecutionError::JournalKeyUnavailable => "final_text_key_unavailable",
                    runne_runtime::provider_execution::RuntimeProviderExecutionError::KeyRetentionUnsupported => "final_text_key_retention_unsupported",
                    runne_runtime::provider_execution::RuntimeProviderExecutionError::JournalCorrupt => "final_text_journal_corrupt",
                    runne_runtime::provider_execution::RuntimeProviderExecutionError::PersistenceUnavailable => "final_text_persistence_unavailable",
                    runne_runtime::provider_execution::RuntimeProviderExecutionError::AdapterStreamUnavailable => "final_text_adapter_unavailable",
                    runne_runtime::provider_execution::RuntimeProviderExecutionError::JournalCommitLost => "final_text_commit_lost",
                    runne_runtime::provider_execution::RuntimeProviderExecutionError::RecoveryFrozen => "final_text_recovery_frozen",
                    runne_runtime::provider_execution::RuntimeProviderExecutionError::TerminalRejected => "final_text_terminal_rejected",
                    runne_runtime::provider_execution::RuntimeProviderExecutionError::PolicyDenied => "final_text_policy_denied",
                    runne_runtime::provider_execution::RuntimeProviderExecutionError::PricingUnavailable => "final_text_pricing_unavailable",
                    runne_runtime::provider_execution::RuntimeProviderExecutionError::ApplicationUnavailable => "final_text_application_unavailable",
                    runne_runtime::provider_execution::RuntimeProviderExecutionError::ApplicationConflict => "final_text_application_conflict",
                });
                CanonicalProviderExecutionError::Uncertain
            })?;
        String::from_utf8(recovered.output().to_vec()).map_err(|_| {
            crate::application::exec_taskrun_worker::d2_stage("final_text_invalid_utf8");
            CanonicalProviderExecutionError::Uncertain
        })
    }
}
