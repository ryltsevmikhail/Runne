impl Lifecycle {
    fn accept_completed(&mut self, event: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
        require_keys(event, &["response", "sequence_number", "type"])?;
        if self.stage == LifecycleStage::ToolItemDone {
            let response = required_object(event, "response")?;
            self.bind_response(response, "completed")?;
            validate_terminal_response_guards(response, false, false)?;
            self.accept_tool_completed(response)?;
            self.push_optional_usage(response)?;
            self.push_normalized(ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::Completed,
                reason: ProviderFinishReason::ToolCalls,
            })?;
            self.stage = LifecycleStage::Terminal;
            return Ok(());
        }
        if self.stage != LifecycleStage::ItemDone {
            return Err(OpenAiStreamError::IllegalTransition);
        }
        let response = required_object(event, "response")?;
        self.bind_response(response, "completed")?;
        validate_terminal_response_guards(response, false, false)?;
        validate_output(response, self.item_id()?, &self.text, "completed", false)?;
        match response.get("usage") {
            Some(value) if !value.is_null() => {
                let usage = parse_usage(value)?;
                self.push_normalized(ProviderStreamEventKind::Usage { usage })?;
            }
            Some(_) | None => self.push_normalized(ProviderStreamEventKind::UsageUnavailable)?,
        }
        self.push_normalized(ProviderStreamEventKind::Finished {
            disposition: ProviderTerminalDisposition::Completed,
            reason: ProviderFinishReason::Stop,
        })?;
        self.stage = LifecycleStage::Terminal;
        Ok(())
    }
}
