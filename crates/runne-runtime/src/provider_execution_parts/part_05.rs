impl<'a, K, S, P> RuntimeProviderExecution<'a, K, S, P>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderTerminalPersistence,
    P: ProviderTerminalPricing,
{
    /// Reconstructs terminal output/usage from the authenticated journal,
    /// applies pinned prohibited-content policy and immutable pricing, then
    /// commits the encrypted accounting/outbox transaction.
    pub fn finalize_terminal_output(
        &self,
        context: &ProviderEventJournalContext,
    ) -> Result<ProviderTerminalCommitOutcome, RuntimeProviderExecutionError> {
        self.finalize_terminal_output_kind(context, ProviderTerminalApplicationKind::TextGeneration)
    }

    /// Settles usage for a scanner-approved provider tool proposal without
    /// routing the serialized proposal to conversation text recovery.
    pub fn finalize_tool_terminal_output(
        &self,
        context: &ProviderEventJournalContext,
    ) -> Result<ProviderTerminalCommitOutcome, RuntimeProviderExecutionError> {
        self.finalize_terminal_output_kind(context, ProviderTerminalApplicationKind::ToolProposal)
    }

    fn finalize_terminal_output_kind(
        &self,
        context: &ProviderEventJournalContext,
        application_kind: ProviderTerminalApplicationKind,
    ) -> Result<ProviderTerminalCommitOutcome, RuntimeProviderExecutionError> {
        if self
            .redaction
            .terminal_disposition(context.attempt_id)
            .map_err(|_| RuntimeProviderExecutionError::PolicyDenied)?
            != Some(runne_provider::ScannerTerminalDisposition::Completed)
        {
            return Err(RuntimeProviderExecutionError::PolicyDenied);
        }
        let encrypted_journal = self
            .store
            .load_encrypted_events(context.attempt_id)
            .map_err(map_execution_error)?;
        let (events, journal_keys) = self.decrypt_terminal_journal(&encrypted_journal)?;
        let assembled = if application_kind == ProviderTerminalApplicationKind::ToolProposal {
            assemble_tool_terminal_stream(&events)?
        } else {
            assemble_terminal_stream(&events)?
        };
        if assembled.disposition == ProviderTerminalDisposition::Completed {
            match self.prohibited_content.inspect(
                CanonicalContentBoundary::CanonicalMutation,
                &assembled.output,
            ) {
                Ok(ContentDisposition::Allowed { .. }) => {}
                Ok(ContentDisposition::Prohibited { .. }) | Err(_) => {
                    return Err(RuntimeProviderExecutionError::PolicyDenied);
                }
            }
        }
        if let Some(outcome) =
            self.replay_unknown_terminal(context, &encrypted_journal, &journal_keys, &assembled)?
        {
            return Ok(outcome);
        }
        let (usage, charge_micros, currency, pricing_binding) = match assembled.usage {
            TerminalUsageEvidence::Exact(usage) => {
                let pricing_binding = self
                    .store
                    .load_terminal_pricing_binding(context.attempt_id)
                    .map_err(map_execution_error)?;
                let priced = self.pricing.price_terminal_usage(
                    pricing_binding.pricing_revision_digest(),
                    &context.profile_digest,
                    pricing_binding.effect_started_at(),
                    usage,
                );
                match priced {
                    Ok(priced) if priced.currency() == pricing_binding.currency() => (
                        usage,
                        priced.charge_micros(),
                        priced.currency().to_owned(),
                        pricing_binding,
                    ),
                    Ok(_) => {
                        return self.commit_unknown_terminal(
                            context,
                            &encrypted_journal,
                            &journal_keys,
                            &assembled,
                            Some(usage),
                            ProviderUnknownAccountingReason::CurrencyMismatch,
                        );
                    }
                    Err(runne_provider::ProviderTerminalPricingError::Unavailable) => {
                        return self.commit_unknown_terminal(
                            context,
                            &encrypted_journal,
                            &journal_keys,
                            &assembled,
                            Some(usage),
                            ProviderUnknownAccountingReason::PricingUnavailable,
                        );
                    }
                    Err(runne_provider::ProviderTerminalPricingError::InvalidQuote) => {
                        return self.commit_unknown_terminal(
                            context,
                            &encrypted_journal,
                            &journal_keys,
                            &assembled,
                            Some(usage),
                            ProviderUnknownAccountingReason::PricingInvalid,
                        );
                    }
                }
            }
            TerminalUsageEvidence::Unavailable => {
                return self.commit_unknown_terminal(
                    context,
                    &encrypted_journal,
                    &journal_keys,
                    &assembled,
                    None,
                    ProviderUnknownAccountingReason::UsageUnavailable,
                );
            }
        };
        let terminal = encrypted_journal
            .iter()
            .find(|record| record.sequence == assembled.terminal_sequence && record.terminal)
            .ok_or(RuntimeProviderExecutionError::TerminalRejected)?;
        if terminal.call_digest_version != context.call_digest_version
            || terminal.profile_digest != context.profile_digest
            || terminal.runtime_generation != context.runtime_generation
        {
            return Err(RuntimeProviderExecutionError::TerminalRejected);
        }
        let outbox_id = stable_outbox_id(context, assembled.terminal_sequence);
        let settlement_digest = settlement_digest(
            context,
            &pricing_binding,
            assembled.terminal_sequence,
            &assembled.output,
            usage,
            false,
            assembled.disposition,
            charge_micros,
            &currency,
        );
        let settlement_digest = application_settlement_digest(application_kind, settlement_digest);
        let application_idempotency_key = terminal_application_key(context.attempt_id);
        let encrypted_output = if assembled.disposition == ProviderTerminalDisposition::Completed {
            let material = journal_keys
                .iter()
                .find(|(binding, _)| *binding == terminal.key)
                .map(|(_, material)| material)
                .ok_or(RuntimeProviderExecutionError::JournalKeyUnavailable)?;
            let aad = outbox_aad(
                context,
                terminal.key,
                assembled.terminal_sequence,
                outbox_id,
            );
            Some(self.seal(material, &aad, &assembled.output)?)
        } else {
            None
        };
        self.store
            .commit_terminal(&ProviderTerminalCommitRequest {
                application_kind,
                outbox_id,
                attempt_id: context.attempt_id,
                fencing_token: context.fencing_token,
                terminal_sequence: assembled.terminal_sequence,
                call_digest_version: context.call_digest_version,
                key: terminal.key,
                encrypted_output,
                runtime_generation: context.runtime_generation,
                profile_digest: context.profile_digest,
                usage,
                usage_unavailable: false,
                disposition: assembled.disposition,
                charge_micros,
                currency,
                settlement_digest,
                application_idempotency_key,
            })
            .map_err(map_execution_error)
    }
}
