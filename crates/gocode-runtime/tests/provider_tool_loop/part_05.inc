struct TestRedaction;

static TEST_REDACTION: TestRedaction = TestRedaction;

impl gocode_runtime::provider_redaction::ProviderEventRedaction for TestRedaction {
    fn scan_before_journal(
        &self,
        _context: &gocode_runtime::provider_execution::ProviderEventJournalContext,
        event: &ProviderStreamEvent,
    ) -> Result<
        gocode_runtime::provider_redaction::PreJournalProviderEvent,
        gocode_runtime::provider_redaction::ProviderRedactionError,
    > {
        use gocode_runtime::provider_redaction::PreJournalProviderEvent;
        let kind = match event.kind() {
            ProviderStreamEventKind::Finished {
                disposition,
                reason,
            } => ProviderStreamEventKind::ScannerCompleted {
                text: String::new(),
                disposition: *disposition,
                reason: reason.clone(),
            },
            ProviderStreamEventKind::ScannerCompleted { .. }
            | ProviderStreamEventKind::ScannerProgress => {
                return Ok(PreJournalProviderEvent::Terminal(
                    gocode_provider::ScannerTerminalDisposition::Uncertain(
                        gocode_provider::ScannerUncertainReason::RedactionScannerUnavailable,
                    ),
                ));
            }
            _ => return Ok(PreJournalProviderEvent::Append(event.clone())),
        };
        Ok(PreJournalProviderEvent::Append(
            ProviderStreamEvent::new(event.sequence(), kind).unwrap(),
        ))
    }

    fn terminal_disposition(
        &self,
        _attempt: DispatchAttemptId,
    ) -> Result<
        Option<gocode_provider::ScannerTerminalDisposition>,
        gocode_runtime::provider_redaction::ProviderRedactionError,
    > {
        Ok(Some(
            gocode_provider::ScannerTerminalDisposition::Completed,
        ))
    }
}

fn tool_loop_context() -> gocode_runtime::provider_execution::ProviderEventJournalContext {
    gocode_runtime::provider_execution::ProviderEventJournalContext {
        attempt_id: DispatchAttemptId::from_bytes([30; 16]),
        fencing_token: 3,
        call_digest_version: ProviderCallDigestVersion::V2,
        profile_digest: [4; 32],
        runtime_generation: 5,
    }
}

fn test_loop<J, T>(
    journal: J,
    tool_handoff: T,
    max_text_bytes: usize,
) -> Result<ProviderToolLoop<'static, J, T>, ProviderToolLoopError>
where
    J: ProviderToolJournal,
    T: ToolCallHandoffPort,
{
    ProviderToolLoop::new(
        journal,
        tool_handoff,
        max_text_bytes,
        &TEST_REDACTION,
        tool_loop_context(),
    )
}
