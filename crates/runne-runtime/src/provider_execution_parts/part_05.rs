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
        if self
            .redaction
            .terminal_disposition(context.attempt_id)
            .map_err(|_| RuntimeProviderExecutionError::PolicyDenied)?
            != Some(runne_provider::ScannerTerminalDisposition::Completed)
        {
            return Err(RuntimeProviderExecutionError::PolicyDenied);
        }
        let pricing_binding = self
            .store
            .load_terminal_pricing_binding(context.attempt_id)
            .map_err(map_execution_error)?;
        let events = self.recover_events(context.attempt_id)?;
        let assembled = assemble_terminal_stream(&events)?;
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
        let (usage, usage_unavailable, charge_micros, currency) = match assembled.usage {
            TerminalUsageEvidence::Exact(usage) => {
                let priced = self
                    .pricing
                    .price_terminal_usage(
                        pricing_binding.pricing_revision_digest(),
                        &context.profile_digest,
                        pricing_binding.effect_started_at(),
                        usage,
                    )
                    .map_err(|_| RuntimeProviderExecutionError::PricingUnavailable)?;
                if priced.currency() != pricing_binding.currency() {
                    return Err(RuntimeProviderExecutionError::PricingUnavailable);
                }
                (
                    usage,
                    false,
                    priced.charge_micros(),
                    priced.currency().to_owned(),
                )
            }
            TerminalUsageEvidence::Unavailable => price_unavailable_usage(
                self.pricing,
                &pricing_binding,
                &context.profile_digest,
            )?,
        };
        let terminal = self
            .store
            .load_encrypted_events(context.attempt_id)
            .map_err(map_execution_error)?
            .into_iter()
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
            usage_unavailable,
            assembled.disposition,
            charge_micros,
            &currency,
        );
        let application_idempotency_key = terminal_application_key(context.attempt_id);
        let encrypted_output = if assembled.disposition == ProviderTerminalDisposition::Completed {
            let material = self.load_key(terminal.key)?;
            let aad = outbox_aad(
                context,
                terminal.key,
                assembled.terminal_sequence,
                outbox_id,
            );
            Some(self.seal(&material, &aad, &assembled.output)?)
        } else {
            None
        };
        self.store
            .commit_terminal(&ProviderTerminalCommitRequest {
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
                usage_unavailable,
                disposition: assembled.disposition,
                charge_micros,
                currency,
                settlement_digest,
                application_idempotency_key,
            })
            .map_err(map_execution_error)
    }
}
struct AssembledTerminal {
    output: Zeroizing<Vec<u8>>,
    usage: TerminalUsageEvidence,
    disposition: ProviderTerminalDisposition,
    terminal_sequence: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalUsageEvidence {
    Exact(ProviderUsage),
    Unavailable,
}

fn assemble_terminal_stream(
    events: &[ProviderStreamEvent],
) -> Result<AssembledTerminal, RuntimeProviderExecutionError> {
    let mut validator = ProviderStreamValidator::default();
    let mut output = Zeroizing::new(Vec::new());
    let mut usage = None;
    let mut terminal = None;
    for event in events {
        validator
            .accept(event)
            .map_err(|_| RuntimeProviderExecutionError::TerminalRejected)?;
        match event.kind() {
            ProviderStreamEventKind::Started => {}
            ProviderStreamEventKind::ScannerProgress => {}
            ProviderStreamEventKind::TextDelta { text } => {
                let current_len = output.len();
                let next_len = current_len
                    .checked_add(text.len())
                    .filter(|length| *length <= MAX_PROVIDER_ASSEMBLED_OUTPUT_BYTES)
                    .ok_or(RuntimeProviderExecutionError::TerminalRejected)?;
                output.reserve(next_len - current_len);
                output.extend_from_slice(text.as_bytes());
            }
            ProviderStreamEventKind::Usage { usage: exact_usage } => {
                usage = Some(TerminalUsageEvidence::Exact(*exact_usage));
            }
            ProviderStreamEventKind::UsageUnavailable => {
                usage = Some(TerminalUsageEvidence::Unavailable);
            }
            ProviderStreamEventKind::ToolCallRequested { .. } => {
                return Err(RuntimeProviderExecutionError::TerminalRejected);
            }
            ProviderStreamEventKind::Finished {
                disposition,
                reason,
            } => terminal = Some((event.sequence(), *disposition, reason.clone())),
            ProviderStreamEventKind::ScannerCompleted {
                text,
                disposition,
                reason,
            } => {
                let current_len = output.len();
                let next_len = current_len
                    .checked_add(text.len())
                    .filter(|length| *length <= MAX_PROVIDER_ASSEMBLED_OUTPUT_BYTES)
                    .ok_or(RuntimeProviderExecutionError::TerminalRejected)?;
                output.reserve(next_len - current_len);
                output.extend_from_slice(text.as_bytes());
                terminal = Some((event.sequence(), *disposition, reason.clone()));
            }
        }
    }
    let (terminal_sequence, disposition, reason) =
        terminal.ok_or(RuntimeProviderExecutionError::TerminalRejected)?;
    if events.last().map(ProviderStreamEvent::sequence) != Some(terminal_sequence) {
        return Err(RuntimeProviderExecutionError::TerminalRejected);
    }
    let usage = usage.ok_or(RuntimeProviderExecutionError::TerminalRejected)?;
    let valid_terminal = match (disposition, &reason, usage) {
        (
            ProviderTerminalDisposition::Completed,
            ProviderFinishReason::Stop,
            TerminalUsageEvidence::Exact(_),
        ) => !output.is_empty(),
        (
            ProviderTerminalDisposition::RemoteFailed,
            ProviderFinishReason::Error,
            TerminalUsageEvidence::Exact(_) | TerminalUsageEvidence::Unavailable,
        ) => true,
        (
            ProviderTerminalDisposition::RemoteIncomplete,
            ProviderFinishReason::Length
            | ProviderFinishReason::ContentFilter
            | ProviderFinishReason::Error,
            TerminalUsageEvidence::Exact(_) | TerminalUsageEvidence::Unavailable,
        ) => true,
        _ => false,
    };
    if !valid_terminal {
        return Err(RuntimeProviderExecutionError::TerminalRejected);
    }
    Ok(AssembledTerminal {
        output,
        usage,
        disposition,
        terminal_sequence,
    })
}

fn stable_outbox_id(context: &ProviderEventJournalContext, terminal_sequence: u64) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(PROVIDER_OUTBOX_ID_V1);
    hasher.update(context.attempt_id.as_bytes());
    hasher.update(context.fencing_token.to_be_bytes());
    hasher.update(context.runtime_generation.to_be_bytes());
    hasher.update(terminal_sequence.to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut identity = [0_u8; 16];
    identity.copy_from_slice(&digest[..16]);
    if identity == [0; 16] {
        identity[15] = 1;
    }
    identity
}

fn terminal_application_key(attempt_id: DispatchAttemptId) -> String {
    let mut key = String::with_capacity(53);
    key.push_str("provider-terminal-v1:");
    for byte in attempt_id.as_bytes() {
        let _ = write!(&mut key, "{byte:02x}");
    }
    key
}
#[allow(clippy::too_many_arguments)]
fn settlement_digest(
    context: &ProviderEventJournalContext,
    pricing: &ProviderTerminalPricingBinding,
    terminal_sequence: u64,
    output: &[u8],
    usage: ProviderUsage,
    usage_unavailable: bool,
    disposition: ProviderTerminalDisposition,
    charge_micros: u64,
    currency: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PROVIDER_SETTLEMENT_V2);
    hasher.update(context.attempt_id.as_bytes());
    hasher.update(context.fencing_token.to_be_bytes());
    hasher.update(context.runtime_generation.to_be_bytes());
    hasher.update(context.profile_digest);
    hasher.update(pricing.pricing_revision_digest());
    hasher.update(terminal_sequence.to_be_bytes());
    hasher.update(Sha256::digest(output));
    hasher.update(usage.input_tokens().to_be_bytes());
    hasher.update(usage.output_tokens().to_be_bytes());
    hasher.update(usage.cached_input_tokens().to_be_bytes());
    hasher.update(usage.reasoning_output_tokens().to_be_bytes());
    hasher.update([u8::from(usage_unavailable)]);
    hasher.update([terminal_disposition_code(disposition)]);
    hasher.update(charge_micros.to_be_bytes());
    hasher.update(currency.as_bytes());
    hasher.finalize().into()
}

const fn terminal_disposition_code(disposition: ProviderTerminalDisposition) -> u8 {
    match disposition {
        ProviderTerminalDisposition::Completed => 1,
        ProviderTerminalDisposition::RemoteFailed => 2,
        ProviderTerminalDisposition::RemoteIncomplete => 3,
        ProviderTerminalDisposition::CancelledUncertain => 4,
    }
}
