/// Same-snapshot, same-transaction persistence for a runtime-authenticated
/// remote terminal fact and its source-bound TaskRun generation.
pub trait ProviderRemoteTerminalSourcePersistence: Send + Sync {
    /// Persists the exact factual outcome plus any priceable usage. The
    /// callback authenticates the exact snapshot loaded in the writer's
    /// transaction, including its encrypted artifact and AAD.
    fn commit_remote_terminal_source(
        &self,
        request: &ProviderRemoteTerminalSourceCommit,
        authenticate: &dyn Fn(
            &runne_application::provider::ProviderRemoteAttemptRecord,
        ) -> Result<(), ProviderExecutionError>,
    ) -> Result<ProviderRemoteTerminalSourceOutcome, ProviderExecutionError>;
}

impl<K, S> RuntimeProviderRemoteIdentityCommitter<K, S>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore
        + ProviderRemoteRecoveryStore
        + ProviderRemoteTerminalSourcePersistence
        + ?Sized,
{
    /// Authenticates one persisted terminal snapshot, prices only exact usage
    /// under the historical admission, then asks the store to pin its source.
    #[doc(hidden)]
    pub fn commit_authenticated_remote_terminal_source<P: ProviderTerminalPricing>(
        &self,
        expected: ProviderRecoveryBinding,
        pricing: &P,
    ) -> Result<ProviderRemoteTerminalSourceOutcome, ProviderRecoveryError> {
        let snapshot = self
            .store
            .load_remote_attempt(expected.provider_attempt_id())
            .map_err(|_| ProviderRecoveryError::Unavailable)?
            .ok_or(ProviderRecoveryError::Unavailable)?;
        let record = self
            .store
            .load_terminal_pricing_binding(expected.provider_attempt_id())
            .map_err(|_| ProviderRecoveryError::Unavailable)?;
        let identity = self
            .load_persisted_attempt(expected)?
            .ok_or(ProviderRecoveryError::Unavailable)?;
        if record.pricing_revision_digest() != identity.identity().pricing_digest()
            || record.pricing_revision_digest() != &snapshot.request.binding.pricing_digest
        {
            return Err(ProviderRecoveryError::InvalidIdentity);
        }
        let artifact = self
            .authenticate_remote_terminal_snapshot(
                &snapshot,
                identity.identity(),
                expected.task_run_id(),
                expected.task_attempt_id(),
            )?
            .ok_or(ProviderRecoveryError::InvalidIdentity)?;
        let (status, usage) = match artifact.status() {
            runne_provider::ProviderRemoteResponseStatus::Completed { usage } => {
                (ProviderRemoteTerminalDisposition::Completed, *usage)
            }
            runne_provider::ProviderRemoteResponseStatus::Failed { usage, .. } => {
                (ProviderRemoteTerminalDisposition::Failed, *usage)
            }
            runne_provider::ProviderRemoteResponseStatus::Incomplete { usage, .. } => {
                (ProviderRemoteTerminalDisposition::Incomplete, *usage)
            }
            runne_provider::ProviderRemoteResponseStatus::Cancelled { usage } => {
                (ProviderRemoteTerminalDisposition::Cancelled, *usage)
            }
            runne_provider::ProviderRemoteResponseStatus::Pending
            | runne_provider::ProviderRemoteResponseStatus::Unknown => {
                return Err(ProviderRecoveryError::InvalidIdentity);
            }
        };
        let mut charge_micros = None;
        let mut currency = None;
        let mut digest = None;
        if let Some(usage) = usage {
            let within_reservation = usage.total_tokens()
                <= record
                    .reserved_input_tokens()
                    .saturating_add(record.reserved_output_tokens());
            if within_reservation {
                if let Ok(priced) = pricing.price_terminal_usage(
                    record.pricing_revision_digest(),
                    identity.identity().profile_digest(),
                    record.effect_started_at(),
                    usage,
                ) {
                    if priced.currency() == record.currency()
                        && priced.charge_micros() <= record.reserved_cost_micros()
                    {
                        let value = remote_terminal_settlement_digest(
                            &snapshot,
                            &artifact,
                            status,
                            usage,
                            priced.charge_micros(),
                            priced.currency(),
                        );
                        charge_micros = Some(priced.charge_micros());
                        currency = Some(priced.currency().to_owned());
                        digest = Some(value);
                    }
                }
            }
        }
        let request = ProviderRemoteTerminalSourceCommit::from_authenticated_terminal(
            expected.provider_attempt_id(),
            expected.task_run_id(),
            expected.task_attempt_id(),
            *identity.identity().runtime_authority_id(),
            identity.identity().database_generation(),
            identity.identity().runtime_generation(),
            identity.identity().fencing_token(),
            *identity.identity().request_digest(),
            *snapshot
                .response
                .as_ref()
                .ok_or(ProviderRecoveryError::InvalidIdentity)?
                .encrypted_response_id
                .plaintext_digest(),
            *snapshot
                .terminal
                .as_ref()
                .ok_or(ProviderRecoveryError::InvalidIdentity)?
                .encrypted_artifact
                .plaintext_digest(),
            terminal_output_digest(&artifact),
            *identity.identity().profile_digest(),
            *identity.identity().pricing_digest(),
            status,
            artifact.publication_disposition(),
            usage,
            charge_micros,
            currency,
            digest,
        )
        .map_err(|_| ProviderRecoveryError::InvalidIdentity)?;
        let authenticate = |current: &runne_application::provider::ProviderRemoteAttemptRecord| {
            let artifact = self
                .authenticate_remote_terminal_snapshot(
                    current,
                    identity.identity(),
                    expected.task_run_id(),
                    expected.task_attempt_id(),
                )
                .map_err(|_| ProviderExecutionError::TerminalConflict)?
                .ok_or(ProviderExecutionError::TerminalConflict)?;
            let (current_status, current_usage) = match artifact.status() {
                runne_provider::ProviderRemoteResponseStatus::Completed { usage } => {
                    (ProviderRemoteTerminalDisposition::Completed, *usage)
                }
                runne_provider::ProviderRemoteResponseStatus::Failed { usage, .. } => {
                    (ProviderRemoteTerminalDisposition::Failed, *usage)
                }
                runne_provider::ProviderRemoteResponseStatus::Incomplete { usage, .. } => {
                    (ProviderRemoteTerminalDisposition::Incomplete, *usage)
                }
                runne_provider::ProviderRemoteResponseStatus::Cancelled { usage } => {
                    (ProviderRemoteTerminalDisposition::Cancelled, *usage)
                }
                runne_provider::ProviderRemoteResponseStatus::Pending
                | runne_provider::ProviderRemoteResponseStatus::Unknown => {
                    return Err(ProviderExecutionError::TerminalConflict);
                }
            };
            if current_status != request.terminal_status()
                || current_usage != request.usage()
                || artifact.publication_disposition() != request.publication_disposition()
                || terminal_output_digest(&artifact) != request.output_digest().copied()
                || current.terminal.as_ref().is_none_or(|saved| {
                    saved.encrypted_artifact.plaintext_digest() != request.artifact_digest()
                })
            {
                return Err(ProviderExecutionError::TerminalConflict);
            }
            Ok(())
        };
        let result = self
            .store
            .commit_remote_terminal_source(&request, &authenticate);
        result.map_err(|error| match error {
            ProviderExecutionError::TerminalConflict
            | ProviderExecutionError::StaleGeneration
            | ProviderExecutionError::AttemptUncertain => ProviderRecoveryError::InvalidIdentity,
            _ => ProviderRecoveryError::Unavailable,
        })
    }
}
