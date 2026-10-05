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
        let text = recovery.text().to_owned();
        let usage = recovery.usage();
        let usage_unavailable = recovery.usage_unavailable();
        let deadline = tokio::time::Instant::now() + TOOL_RESPONSE_DEADLINE;
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
                    | ProviderToolRecoveryStatus::ToolProposalReady { .. }
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
            ProviderToolRecoveryStatus::ToolProposalReady { call } => {
                return Ok(ProviderToolLoopOutcome::ToolProposalReady {
                    call: call.clone(),
                    text,
                    usage,
                    usage_unavailable,
                });
            }
            ProviderToolRecoveryStatus::Cancelled => {
                return Ok(ProviderToolLoopOutcome::Cancelled);
            }
        }
        let mut collector = match CommittedToolProposalCollector::new(
            cursor,
            text,
            usage,
            usage_unavailable,
            self.max_text_bytes,
        ) {
            Ok(collector) => collector,
            Err(_) => return self.freeze(stream_id, "provider_journal"),
        };
        loop {
            if cursor >= MAX_PROVIDER_TOOL_EVENTS {
                return self.freeze(stream_id, "provider_event_bound");
            }
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
                _ = tokio::time::sleep_until(deadline) => {
                    return self.freeze(stream_id, "provider_response_deadline");
                }
                item = provider.next(&stream_id, StreamCursor::new(cursor)) => item,
            };
            let item = match item {
                Ok(item) => item,
                Err(_) => return self.freeze(stream_id, "provider_stream"),
            };
            let provider_event = item.event();
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
            let mut next_collector = collector.clone();
            let terminal = match next_collector.accept_committed(&event, self.scanner_completed()) {
                Ok(terminal) => terminal,
                Err(reason) => return self.freeze(stream_id, reason),
            };
            self.journal.append_provider_event(stream_id, &event)?;
            cursor = cursor
                .checked_add(1)
                .ok_or(ProviderToolLoopError::MalformedStream)?;
            collector = next_collector;
            if let Some(outcome) = terminal {
                return match outcome {
                    ProviderToolLoopOutcome::ToolProposalReady { call, .. } => {
                        self.journal
                            .append(ProviderToolTransition::ToolProposalReady {
                                stream_id,
                                call: call.clone(),
                            })?;
                        Ok(ProviderToolLoopOutcome::ToolProposalReady {
                            call,
                            text: collector.text.clone(),
                            usage: collector.usage,
                            usage_unavailable: collector.usage_unavailable,
                        })
                    }
                    other => Ok(other),
                };
            }
        }
    }
}
