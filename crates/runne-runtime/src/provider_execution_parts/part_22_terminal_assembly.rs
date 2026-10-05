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

impl TerminalUsageEvidence {
    fn exact(self) -> Option<ProviderUsage> {
        match self {
            Self::Exact(usage) => Some(usage),
            Self::Unavailable => None,
        }
    }
}

fn assemble_terminal_stream(
    events: &[ProviderStreamEvent],
) -> Result<AssembledTerminal, RuntimeProviderExecutionError> {
    assemble_terminal_stream_mode(events, false)
}

fn assemble_tool_terminal_stream(
    events: &[ProviderStreamEvent],
) -> Result<AssembledTerminal, RuntimeProviderExecutionError> {
    assemble_terminal_stream_mode(events, true)
}

fn assemble_terminal_stream_mode(
    events: &[ProviderStreamEvent],
    allow_tool_call: bool,
) -> Result<AssembledTerminal, RuntimeProviderExecutionError> {
    let mut validator = ProviderStreamValidator::default();
    let mut output = Zeroizing::new(Vec::new());
    let mut usage = None;
    let mut terminal = None;
    let mut tool_call_seen = false;
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
            ProviderStreamEventKind::ToolCallRequested {
                call_id,
                tool_name,
                arguments_json,
            } => {
                if !allow_tool_call
                    || tool_call_seen
                    || !output.is_empty()
                    || call_id.len() > 128
                    || tool_name.len() > 128
                    || arguments_json.len() > 8 * 1024
                {
                    return Err(RuntimeProviderExecutionError::TerminalRejected);
                }
                output.extend_from_slice(
                    &serde_json::to_vec(&(call_id, tool_name, arguments_json))
                        .map_err(|_| RuntimeProviderExecutionError::TerminalRejected)?,
                );
                tool_call_seen = true;
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
            TerminalUsageEvidence::Exact(_) | TerminalUsageEvidence::Unavailable,
        ) => !tool_call_seen && !output.is_empty(),
        (
            ProviderTerminalDisposition::Completed,
            ProviderFinishReason::ToolCalls,
            TerminalUsageEvidence::Exact(_) | TerminalUsageEvidence::Unavailable,
        ) => allow_tool_call && tool_call_seen && !output.is_empty(),
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

fn application_settlement_digest(
    kind: ProviderTerminalApplicationKind,
    digest: [u8; 32],
) -> [u8; 32] {
    if kind == ProviderTerminalApplicationKind::TextGeneration {
        return digest;
    }
    Sha256::new()
        .chain_update(b"GOCODE_PROVIDER_TOOL_PROPOSAL_SETTLEMENT_V1\0")
        .chain_update(digest)
        .finalize()
        .into()
}
