impl<'a, J, T> ProviderToolLoop<'a, J, T>
where
    J: ProviderToolJournal,
    T: ToolCallHandoffPort,
{
    /// Constructs a pump with a non-zero text bound.
    pub fn new(
        journal: J,
        tool_handoff: T,
        max_text_bytes: usize,
        redaction: &'a dyn ProviderEventRedaction,
        journal_context: ProviderEventJournalContext,
    ) -> Result<Self, ProviderToolLoopError> {
        if max_text_bytes == 0 {
            return Err(ProviderToolLoopError::TextTooLarge);
        }
        Ok(Self {
            journal,
            tool_handoff,
            max_text_bytes,
            redaction,
            journal_context,
        })
    }

    /// Polls one stream until terminal, tool handoff, cancellation or uncertainty.
    pub async fn run<P: ProviderPort>(
        &self,
        provider: &P,
        stream_id: ProviderStreamId,
        cancellation: &CancellationToken,
    ) -> Result<ProviderToolLoopOutcome, ProviderToolLoopError> {
        let recovery = self.journal.recovery_state(stream_id)?;
        let mut cursor = recovery.next_cursor();
        let mut text = recovery.text().to_owned();
        let mut usage = recovery.usage();
        let mut usage_unavailable = recovery.usage_unavailable();
        if text.len() > self.max_text_bytes {
            return self.freeze(stream_id, "journal_text_bound");
        }
        if usage.is_some() && usage_unavailable {
            return self.freeze(stream_id, "provider_journal");
        }
        if recovery.next_cursor() == 0
            && matches!(
                recovery.status(),
                ProviderToolRecoveryStatus::Terminal { .. }
                    | ProviderToolRecoveryStatus::ToolCallPending { .. }
                    | ProviderToolRecoveryStatus::ToolResultReady { .. }
            )
        {
            return self.freeze(stream_id, "provider_journal");
        }
        match recovery.status() {
            ProviderToolRecoveryStatus::Active => {}
            ProviderToolRecoveryStatus::Terminal {
                disposition: ProviderTerminalDisposition::Completed,
                reason: ProviderFinishReason::Stop,
            } if !usage_unavailable && self.scanner_completed() => {
                return Ok(ProviderToolLoopOutcome::Completed { text, usage });
            }
            ProviderToolRecoveryStatus::Terminal {
                disposition,
                reason,
            } if valid_remote_terminal(disposition, reason)
                && (usage.is_some() || usage_unavailable)
                && self.scanner_completed() =>
            {
                return Ok(ProviderToolLoopOutcome::RemoteTerminal {
                    disposition: *disposition,
                    reason: reason.clone(),
                    text,
                    usage,
                    usage_unavailable,
                });
            }
            ProviderToolRecoveryStatus::Terminal { .. } => {
                return self.freeze(stream_id, "terminal_reason");
            }
            ProviderToolRecoveryStatus::ToolCallPending { .. }
            | ProviderToolRecoveryStatus::CancellationPending
            | ProviderToolRecoveryStatus::Frozen => {
                return Ok(ProviderToolLoopOutcome::Uncertain);
            }
            ProviderToolRecoveryStatus::ToolResultReady {
                call_id,
                result_digest,
            } => {
                return Ok(ProviderToolLoopOutcome::ToolResultReady {
                    call_id: call_id.clone(),
                    result_digest: *result_digest,
                });
            }
            ProviderToolRecoveryStatus::Cancelled => {
                return Ok(ProviderToolLoopOutcome::Cancelled);
            }
        }
        let mut validator = match ProviderStreamValidator::resume_at(
            cursor,
            usage.is_some() || usage_unavailable,
        ) {
            Ok(validator) => validator,
            Err(_) => return self.freeze(stream_id, "provider_journal"),
        };
        loop {
            let item = tokio::select! {
                biased;
                _ = cancellation.cancelled() => {
                    self.journal.append(ProviderToolTransition::CancellationIntent {
                        stream_id,
                    })?;
                    provider.cancel(CancelRequest::new(stream_id)).await
                        .map_err(|_| ProviderToolLoopError::ProviderFailed)?;
                    self.journal.append(
                        ProviderToolTransition::CancellationAcknowledged { stream_id }
                    )?;
                    return Ok(ProviderToolLoopOutcome::Cancelled);
                }
                item = provider.next(&stream_id, StreamCursor::new(cursor)) => item,
            };
            let item = match item {
                Ok(item) => item,
                Err(_) => return self.freeze(stream_id, "provider_stream"),
            };
            let provider_event = item.event();
            if validator.accept(provider_event).is_err() {
                return self.freeze(stream_id, "provider_grammar");
            }
            let event = match self
                .redaction
                .scan_before_journal(&self.journal_context, provider_event)
            {
                Ok(PreJournalProviderEvent::Append(event))
                    if event.sequence() == provider_event.sequence() =>
                {
                    event
                }
                Ok(PreJournalProviderEvent::Append(_))
                | Ok(PreJournalProviderEvent::Terminal(_))
                | Err(_) => return self.freeze(stream_id, "scanner_boundary"),
            };
            let released_text = match event.kind() {
                ProviderStreamEventKind::TextDelta { text }
                | ProviderStreamEventKind::ScannerCompleted { text, .. } => Some(text),
                _ => None,
            };
            if let Some(delta) = released_text {
                let next = text
                    .len()
                    .checked_add(delta.len())
                    .ok_or(ProviderToolLoopError::TextTooLarge)?;
                if next > self.max_text_bytes {
                    return self.freeze(stream_id, "text_bound");
                }
            }
            self.journal.append_provider_event(stream_id, &event)?;
            cursor = cursor
                .checked_add(1)
                .ok_or(ProviderToolLoopError::MalformedStream)?;

            match event.kind() {
                ProviderStreamEventKind::Started => {}
                ProviderStreamEventKind::TextDelta { text: delta } => {
                    text.push_str(delta);
                }
                ProviderStreamEventKind::Usage { usage: event_usage } => {
                    if usage_unavailable || usage.replace(*event_usage).is_some() {
                        return self.freeze(stream_id, "duplicate_usage");
                    }
                }
                ProviderStreamEventKind::UsageUnavailable => {
                    if usage.is_some() || usage_unavailable {
                        return self.freeze(stream_id, "duplicate_usage");
                    }
                    usage_unavailable = true;
                }
                ProviderStreamEventKind::ToolCallRequested {
                    call_id,
                    tool_name,
                    arguments_json,
                } => {
                    let call = RuntimeToolCall {
                        call_id: call_id.clone(),
                        tool_name: tool_name.clone(),
                        arguments_json: arguments_json.clone(),
                    };
                    match self.tool_handoff.dispatch(&call) {
                        Ok(ToolHandoffDisposition::Completed { result_digest }) => {
                            self.journal.append(ProviderToolTransition::ToolResult {
                                stream_id,
                                call_id: call.call_id.clone(),
                                result_digest,
                            })?;
                            return Ok(ProviderToolLoopOutcome::ToolResultReady {
                                call_id: call.call_id,
                                result_digest,
                            });
                        }
                        Ok(ToolHandoffDisposition::Uncertain) | Err(_) => {
                            return self.freeze(stream_id, "tool_effect");
                        }
                    }
                }
                ProviderStreamEventKind::Finished {
                    disposition: ProviderTerminalDisposition::Completed,
                    reason: ProviderFinishReason::Stop,
                } if !usage_unavailable && self.scanner_completed() => {
                    return Ok(ProviderToolLoopOutcome::Completed { text, usage });
                }
                ProviderStreamEventKind::Finished {
                    disposition,
                    reason,
                } if valid_remote_terminal(disposition, reason)
                    && (usage.is_some() || usage_unavailable)
                    && self.scanner_completed() =>
                {
                    return Ok(ProviderToolLoopOutcome::RemoteTerminal {
                        disposition: *disposition,
                        reason: reason.clone(),
                        text,
                        usage,
                        usage_unavailable,
                    });
                }
                ProviderStreamEventKind::Finished { .. } => {
                    return self.freeze(stream_id, "terminal_reason");
                }
                ProviderStreamEventKind::ScannerCompleted {
                    text: tail,
                    disposition: ProviderTerminalDisposition::Completed,
                    reason: ProviderFinishReason::Stop,
                } if !usage_unavailable && self.scanner_completed() => {
                    text.push_str(tail);
                    return Ok(ProviderToolLoopOutcome::Completed { text, usage });
                }
                ProviderStreamEventKind::ScannerCompleted {
                    text: tail,
                    disposition,
                    reason,
                } if valid_remote_terminal(disposition, reason)
                    && (usage.is_some() || usage_unavailable)
                    && self.scanner_completed() =>
                {
                    text.push_str(tail);
                    return Ok(ProviderToolLoopOutcome::RemoteTerminal {
                        disposition: *disposition,
                        reason: reason.clone(),
                        text,
                        usage,
                        usage_unavailable,
                    });
                }
                ProviderStreamEventKind::ScannerCompleted { .. } => {
                    return self.freeze(stream_id, "scanner_terminal");
                }
                ProviderStreamEventKind::ScannerProgress => {}
            }
        }
    }

    fn scanner_completed(&self) -> bool {
        matches!(
            self.redaction
                .terminal_disposition(self.journal_context.attempt_id),
            Ok(Some(ScannerTerminalDisposition::Completed))
        )
    }

    fn freeze(
        &self,
        stream_id: ProviderStreamId,
        reason: &'static str,
    ) -> Result<ProviderToolLoopOutcome, ProviderToolLoopError> {
        self.journal
            .append(ProviderToolTransition::Frozen { stream_id, reason })?;
        Ok(ProviderToolLoopOutcome::Uncertain)
    }
}

fn valid_remote_terminal(
    disposition: &ProviderTerminalDisposition,
    reason: &ProviderFinishReason,
) -> bool {
    matches!(
        (disposition, reason),
        (
            ProviderTerminalDisposition::RemoteFailed,
            ProviderFinishReason::Error
        ) | (
            ProviderTerminalDisposition::RemoteIncomplete,
            ProviderFinishReason::Length
                | ProviderFinishReason::ContentFilter
                | ProviderFinishReason::Error
        )
    )
}
