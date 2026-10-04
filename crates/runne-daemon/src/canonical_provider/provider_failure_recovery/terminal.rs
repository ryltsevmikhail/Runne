use super::*;

pub(super) fn assemble_failure(
    events: &[ProviderStreamEvent],
) -> Result<
    (
        u64,
        ProviderTerminalDisposition,
        ProviderUsage,
        bool,
        [u8; 32],
    ),
    (),
> {
    let mut validator = ProviderStreamValidator::default();
    let mut output = Sha256::new();
    let mut length = 0usize;
    let mut usage = None;
    let mut terminal = None;
    for event in events {
        validator.accept(event).map_err(|_| ())?;
        let mut add = |text: &str| -> Result<(), ()> {
            length = length
                .checked_add(text.len())
                .filter(|n| *n <= MAX_RECOVERY_OUTPUT_BYTES)
                .ok_or(())?;
            output.update(text.as_bytes());
            Ok(())
        };
        match event.kind() {
            ProviderStreamEventKind::TextDelta { text } => add(text)?,
            ProviderStreamEventKind::Usage { usage: value } => usage = Some((Some(*value), false)),
            ProviderStreamEventKind::UsageUnavailable => usage = Some((None, true)),
            ProviderStreamEventKind::Finished {
                disposition,
                reason,
            } => terminal = Some((event.sequence(), *disposition, reason.clone())),
            ProviderStreamEventKind::ScannerCompleted {
                text,
                disposition,
                reason,
            } => {
                add(text)?;
                terminal = Some((event.sequence(), *disposition, reason.clone()));
            }
            ProviderStreamEventKind::ToolCallRequested { .. } => return Err(()),
            ProviderStreamEventKind::Started | ProviderStreamEventKind::ScannerProgress => {}
        }
    }
    let (sequence, disposition, reason) = terminal.ok_or(())?;
    if events.last().map(ProviderStreamEvent::sequence) != Some(sequence) {
        return Err(());
    }
    let (usage, unavailable) = usage.ok_or(())?;
    let acceptable = matches!(
        (disposition, reason),
        (
            ProviderTerminalDisposition::RemoteFailed,
            ProviderFinishReason::Error
        ) | (
            ProviderTerminalDisposition::RemoteIncomplete,
            ProviderFinishReason::Length
                | ProviderFinishReason::ContentFilter
                | ProviderFinishReason::Error,
        )
    );
    if !acceptable {
        return Err(());
    }
    Ok((
        sequence,
        disposition,
        usage.unwrap_or(ProviderUsage::new(0, 0, 0, 0).map_err(|_| ())?),
        unavailable,
        output.finalize().into(),
    ))
}

pub(super) fn verify_settlement(
    c: &runne_store::store::provider_failure_recovery::ProviderFailureRecoveryRecord,
    sequence: u64,
    disposition: ProviderTerminalDisposition,
    journal_usage: ProviderUsage,
    unavailable: bool,
    output_digest: [u8; 32],
) -> Result<(), ()> {
    let accounting = ProviderUsage::new(
        c.input_tokens,
        c.output_tokens,
        c.cached_input_tokens,
        c.reasoning_output_tokens,
    )
    .map_err(|_| ())?;
    if !unavailable && accounting != journal_usage {
        return Err(());
    }
    let mut hash = Sha256::new();
    hash.update(SETTLEMENT_DOMAIN);
    hash.update(c.dispatch_attempt_id);
    hash.update(c.provider_fencing_token.to_be_bytes());
    hash.update(c.runtime_generation.to_be_bytes());
    hash.update(c.profile_digest);
    hash.update(c.pricing_revision_digest);
    hash.update(sequence.to_be_bytes());
    hash.update(output_digest);
    hash.update(accounting.input_tokens().to_be_bytes());
    hash.update(accounting.output_tokens().to_be_bytes());
    hash.update(accounting.cached_input_tokens().to_be_bytes());
    hash.update(accounting.reasoning_output_tokens().to_be_bytes());
    hash.update([u8::from(unavailable)]);
    hash.update([match disposition {
        ProviderTerminalDisposition::RemoteFailed => 2,
        ProviderTerminalDisposition::RemoteIncomplete => 3,
        _ => return Err(()),
    }]);
    hash.update(c.charge_micros.to_be_bytes());
    hash.update(c.currency.as_bytes());
    let digest: [u8; 32] = hash.finalize().into();
    if digest != c.settlement_digest {
        return Err(());
    }
    Ok(())
}
