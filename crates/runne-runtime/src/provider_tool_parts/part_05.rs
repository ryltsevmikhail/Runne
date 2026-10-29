/// Collector for provider events that have already passed canonical commit.
/// It performs no polling, journaling, approval or effects.
#[derive(Clone)]
pub struct CommittedToolProposalCollector {
    validator: ProviderStreamValidator,
    cursor: u64,
    text: String,
    usage: Option<ProviderUsage>,
    usage_unavailable: bool,
    calls: Vec<RuntimeToolCall>,
    max_calls: usize,
    terminal_verified: bool,
    max_text_bytes: usize,
    deadline: tokio::time::Instant,
}

impl CommittedToolProposalCollector {
    /// Starts collection for a new or recovered committed prefix.
    pub fn new(
        cursor: u64,
        text: String,
        usage: Option<ProviderUsage>,
        usage_unavailable: bool,
        max_text_bytes: usize,
    ) -> Result<Self, ProviderToolLoopError> {
        let validator =
            ProviderStreamValidator::resume_at(cursor, usage.is_some() || usage_unavailable)
                .map_err(|_| ProviderToolLoopError::MalformedStream)?;
        if max_text_bytes == 0
            || text.len() > max_text_bytes
            || (usage.is_some() && usage_unavailable)
        {
            return Err(ProviderToolLoopError::MalformedStream);
        }
        Ok(Self {
            validator,
            cursor,
            text,
            usage,
            usage_unavailable,
            calls: Vec::new(),
            max_calls: 1,
            terminal_verified: false,
            max_text_bytes,
            deadline: tokio::time::Instant::now() + TOOL_RESPONSE_DEADLINE,
        })
    }

    /// Opts a fresh collector into a bounded batch of independent proposals.
    pub fn with_max_calls(mut self, maximum: usize) -> Result<Self, ProviderToolLoopError> {
        if self.cursor != 0 || !(1..=16).contains(&maximum) {
            return Err(ProviderToolLoopError::MalformedStream);
        }
        self.max_calls = maximum;
        Ok(self)
    }

    /// Returns proposals only after the complete scanner-authenticated terminal.
    pub fn committed_calls(&self) -> &[RuntimeToolCall] {
        if self.terminal_verified {
            &self.calls
        } else {
            &[]
        }
    }

    /// Accepts one canonical committed event and yields only after its valid
    /// complete terminal. Callers must persist the returned proposal before
    /// authorizing approval or any tool effect.
    pub fn accept_committed(
        &mut self,
        event: &ProviderStreamEvent,
        scanner_completed: bool,
    ) -> Result<Option<ProviderToolLoopOutcome>, &'static str> {
        if tokio::time::Instant::now() >= self.deadline
            || self.cursor >= MAX_PROVIDER_TOOL_EVENTS
            || event.sequence() != self.cursor
        {
            return Err("provider_event_bound");
        }
        self.validator
            .accept(event)
            .map_err(|_| "provider_grammar")?;
        match event.kind() {
            ProviderStreamEventKind::Started | ProviderStreamEventKind::ScannerProgress => {}
            ProviderStreamEventKind::TextDelta { text } => self.append_text(text)?,
            ProviderStreamEventKind::ScannerCompleted {
                text,
                disposition,
                reason,
            } => {
                self.append_text(text)?;
                return self.terminal(*disposition, reason, scanner_completed);
            }
            ProviderStreamEventKind::Usage { usage } => {
                if self.usage_unavailable || self.usage.replace(*usage).is_some() {
                    return Err("duplicate_usage");
                }
            }
            ProviderStreamEventKind::UsageUnavailable => {
                if self.usage.is_some() || self.usage_unavailable {
                    return Err("duplicate_usage");
                }
                self.usage_unavailable = true;
            }
            ProviderStreamEventKind::ToolCallRequested {
                call_id,
                tool_name,
                arguments_json,
            } => {
                if arguments_json.len() > MAX_TOOL_PROPOSAL_ARGUMENT_BYTES {
                    return Err("tool_arguments_bound");
                }
                if self.calls.len() >= self.max_calls
                    || self.calls.iter().any(|call| call.call_id == *call_id)
                {
                    return Err("multiple_tool_calls");
                }
                self.calls.push(RuntimeToolCall {
                    call_id: call_id.clone(),
                    tool_name: tool_name.clone(),
                    arguments_json: arguments_json.clone(),
                });
            }
            ProviderStreamEventKind::Finished {
                disposition,
                reason,
            } => {
                return self.terminal(*disposition, reason, scanner_completed);
            }
        }
        self.cursor = self.cursor.checked_add(1).ok_or("provider_event_bound")?;
        Ok(None)
    }

    fn append_text(&mut self, text: &str) -> Result<(), &'static str> {
        if self
            .text
            .len()
            .checked_add(text.len())
            .filter(|n| *n <= self.max_text_bytes)
            .is_none()
        {
            return Err("text_bound");
        }
        self.text.push_str(text);
        Ok(())
    }

    fn proposal(&self) -> Result<Option<ProviderToolLoopOutcome>, &'static str> {
        let Some(call) = self.calls.first().cloned() else {
            return Err("tool_terminal_without_call");
        };
        Ok(Some(ProviderToolLoopOutcome::ToolProposalReady {
            call,
            text: self.text.clone(),
            usage: self.usage,
            usage_unavailable: self.usage_unavailable,
        }))
    }

    fn terminal(
        &mut self,
        disposition: ProviderTerminalDisposition,
        reason: &ProviderFinishReason,
        scanner_completed: bool,
    ) -> Result<Option<ProviderToolLoopOutcome>, &'static str> {
        if !self.calls.is_empty() && *reason != ProviderFinishReason::ToolCalls {
            return Err("tool_terminal_mismatch");
        }
        if disposition == ProviderTerminalDisposition::Completed
            && *reason == ProviderFinishReason::ToolCalls
            && scanner_completed
            && (self.usage.is_some() || self.usage_unavailable)
        {
            self.terminal_verified = true;
            return self.proposal();
        }
        if disposition == ProviderTerminalDisposition::Completed
            && *reason == ProviderFinishReason::Stop
            && self.calls.is_empty()
            && !self.usage_unavailable
            && scanner_completed
        {
            return Ok(Some(ProviderToolLoopOutcome::Completed {
                text: self.text.clone(),
                usage: self.usage,
            }));
        }
        if valid_remote_terminal(&disposition, reason)
            && self.calls.is_empty()
            && (self.usage.is_some() || self.usage_unavailable)
            && scanner_completed
        {
            return Ok(Some(ProviderToolLoopOutcome::RemoteTerminal {
                disposition,
                reason: reason.clone(),
                text: self.text.clone(),
                usage: self.usage,
                usage_unavailable: self.usage_unavailable,
            }));
        }
        Err("terminal_reason")
    }
}
