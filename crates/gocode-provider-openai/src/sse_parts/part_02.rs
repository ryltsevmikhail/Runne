impl Lifecycle {
    fn accept_item_added(&mut self, event: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
        require_keys(event, &["item", "output_index", "sequence_number", "type"])?;
        if self.stage != LifecycleStage::InProgress || required_u64(event, "output_index")? != 0 {
            return Err(OpenAiStreamError::IllegalTransition);
        }
        let item = required_object(event, "item")?;
        validate_added_item(item)?;
        let item_id = required_string(item, "id")?;
        validate_identifier(item_id)?;
        self.item_id = Some(item_id.to_owned());
        self.stage = LifecycleStage::ItemAdded;
        Ok(())
    }

}
impl Lifecycle {
    fn accept_part_added(&mut self, event: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
        require_keys(
            event,
            &[
                "content_index",
                "item_id",
                "output_index",
                "part",
                "sequence_number",
                "type",
            ],
        )?;
        if self.stage != LifecycleStage::ItemAdded {
            return Err(OpenAiStreamError::IllegalTransition);
        }
        self.validate_item_indexes(event)?;
        validate_part(required_object(event, "part")?, "", true)?;
        self.stage = LifecycleStage::PartAdded;
        Ok(())
    }

}
impl Lifecycle {
    fn accept_text_delta(&mut self, event: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
        require_keys_subset(
            event,
            &[
                "content_index",
                "delta",
                "item_id",
                "logprobs",
                "output_index",
                "sequence_number",
                "type",
            ],
            &[
                "content_index",
                "delta",
                "item_id",
                "output_index",
                "sequence_number",
                "type",
            ],
        )?;
        if self.stage != LifecycleStage::PartAdded {
            return Err(OpenAiStreamError::IllegalTransition);
        }
        self.validate_item_indexes(event)?;
        validate_empty_logprobs(event)?;
        let delta = required_string(event, "delta")?;
        if delta.is_empty() {
            return Err(OpenAiStreamError::MalformedEvent);
        }
        let next = self
            .text
            .len()
            .checked_add(delta.len())
            .filter(|length| *length <= OPENAI_MAX_NORMALIZED_TEXT_BYTES)
            .ok_or(OpenAiStreamError::StreamLimitExceeded)?;
        self.text.reserve(next - self.text.len());
        self.text.push_str(delta);
        self.push_normalized(ProviderStreamEventKind::TextDelta {
            text: delta.to_owned(),
        })
    }

}
impl Lifecycle {
    fn accept_text_done(&mut self, event: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
        require_keys_subset(
            event,
            &[
                "content_index",
                "item_id",
                "logprobs",
                "output_index",
                "sequence_number",
                "text",
                "type",
            ],
            &[
                "content_index",
                "item_id",
                "output_index",
                "sequence_number",
                "text",
                "type",
            ],
        )?;
        if self.stage != LifecycleStage::PartAdded {
            return Err(OpenAiStreamError::IllegalTransition);
        }
        self.validate_item_indexes(event)?;
        validate_empty_logprobs(event)?;
        if required_string(event, "text")? != self.text {
            return Err(OpenAiStreamError::CorrelationMismatch);
        }
        self.stage = LifecycleStage::TextDone;
        Ok(())
    }

}
impl Lifecycle {
    fn accept_part_done(&mut self, event: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
        require_keys(
            event,
            &[
                "content_index",
                "item_id",
                "output_index",
                "part",
                "sequence_number",
                "type",
            ],
        )?;
        if self.stage != LifecycleStage::TextDone {
            return Err(OpenAiStreamError::IllegalTransition);
        }
        self.validate_item_indexes(event)?;
        validate_part(required_object(event, "part")?, &self.text, false)?;
        self.stage = LifecycleStage::PartDone;
        Ok(())
    }

}
impl Lifecycle {
    fn accept_item_done(&mut self, event: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
        require_keys(event, &["item", "output_index", "sequence_number", "type"])?;
        if self.stage != LifecycleStage::PartDone || required_u64(event, "output_index")? != 0 {
            return Err(OpenAiStreamError::IllegalTransition);
        }
        validate_completed_item(
            required_object(event, "item")?,
            self.item_id()?,
            &self.text,
            "completed",
        )?;
        self.stage = LifecycleStage::ItemDone;
        Ok(())
    }

}
impl Lifecycle {
    fn accept_completed(&mut self, event: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
        require_keys(event, &["response", "sequence_number", "type"])?;
        if self.stage != LifecycleStage::ItemDone {
            return Err(OpenAiStreamError::IllegalTransition);
        }
        let response = required_object(event, "response")?;
        self.bind_response(response, "completed")?;
        validate_terminal_response_guards(response, false, false)?;
        validate_output(response, self.item_id()?, &self.text, "completed", false)?;
        let usage_value = response
            .get("usage")
            .filter(|value| !value.is_null())
            .ok_or(OpenAiStreamError::InvalidUsage)?;
        let usage = parse_usage(usage_value)?;
        self.push_normalized(ProviderStreamEventKind::Usage { usage })?;
        self.push_normalized(ProviderStreamEventKind::Finished {
            disposition: ProviderTerminalDisposition::Completed,
            reason: ProviderFinishReason::Stop,
        })?;
        self.stage = LifecycleStage::Terminal;
        Ok(())
    }

}
impl Lifecycle {
    fn accept_failed(&mut self, event: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
        require_keys(event, &["response", "sequence_number", "type"])?;
        self.ensure_terminal_prefix_allowed()?;
        let response = required_object(event, "response")?;
        self.bind_response(response, "failed")?;
        validate_terminal_response_guards(response, true, false)?;
        self.accept_optional_terminal_output(response, &["failed", "incomplete"])?;
        self.push_optional_usage(response)?;
        self.push_normalized(ProviderStreamEventKind::Finished {
            disposition: ProviderTerminalDisposition::RemoteFailed,
            reason: ProviderFinishReason::Error,
        })?;
        self.stage = LifecycleStage::Terminal;
        Ok(())
    }

}
impl Lifecycle {
    fn accept_incomplete(&mut self, event: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
        require_keys(event, &["response", "sequence_number", "type"])?;
        self.ensure_terminal_prefix_allowed()?;
        let response = required_object(event, "response")?;
        self.bind_response(response, "incomplete")?;
        validate_terminal_response_guards(response, false, true)?;
        self.accept_optional_terminal_output(response, &["incomplete"])?;
        self.push_optional_usage(response)?;
        let reason = match response
            .get("incomplete_details")
            .and_then(Value::as_object)
            .and_then(|details| details.get("reason"))
            .and_then(Value::as_str)
        {
            Some("max_output_tokens") => ProviderFinishReason::Length,
            Some("content_filter") => ProviderFinishReason::ContentFilter,
            Some(_) | None => ProviderFinishReason::Error,
        };
        self.push_normalized(ProviderStreamEventKind::Finished {
            disposition: ProviderTerminalDisposition::RemoteIncomplete,
            reason,
        })?;
        self.stage = LifecycleStage::Terminal;
        Ok(())
    }

}
impl Lifecycle {
    fn accept_error(&mut self, event: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
        require_keys(
            event,
            &["code", "message", "param", "sequence_number", "type"],
        )?;
        if self.stage != LifecycleStage::Start {
            return Err(OpenAiStreamError::IllegalTransition);
        }
        validate_diagnostic_string(event, "code")?;
        validate_diagnostic_string(event, "message")?;
        if event.get("param").is_none() {
            return Err(OpenAiStreamError::MalformedEvent);
        }
        self.ensure_started()?;
        self.push_normalized(ProviderStreamEventKind::UsageUnavailable)?;
        self.push_normalized(ProviderStreamEventKind::Finished {
            disposition: ProviderTerminalDisposition::RemoteFailed,
            reason: ProviderFinishReason::Error,
        })?;
        self.stage = LifecycleStage::Terminal;
        Ok(())
    }

}
impl Lifecycle {
    fn bind_response(
        &mut self,
        response: &Map<String, Value>,
        expected_status: &str,
    ) -> Result<(), OpenAiStreamError> {
        validate_response_guards(response)?;
        let response_id = required_string(response, "id")?;
        validate_identifier(response_id)?;
        match self.response_id.as_deref() {
            Some(existing) if existing != response_id => {
                return Err(OpenAiStreamError::CorrelationMismatch);
            }
            None => self.response_id = Some(response_id.to_owned()),
            Some(_) => {}
        }
        if required_string(response, "status")? != expected_status {
            return Err(OpenAiStreamError::IllegalTransition);
        }
        Ok(())
    }

}
