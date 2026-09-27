impl Lifecycle {
    fn accept_part_done(&mut self, event: &Map<String, Value>) -> Result<(), DeepSeekStreamError> {
        traced_exact_keys(
            &mut self.trace,
            event,
            &[
                "content_index",
                "item_id",
                "output_index",
                "part",
                "sequence_number",
                "type",
            ],
            DeepSeekDecodeSchemaNode::OutputTextPart,
        )?;
        if self.stage != LifecycleStage::TextDone {
            return Err(DeepSeekStreamError::IllegalTransition);
        }
        self.validate_item_indexes(event)?;
        let part = traced_required_object(
            &mut self.trace,
            event,
            "part",
            DeepSeekDecodeSchemaNode::OutputTextPart,
        )?;
        traced_output_text_part_keys(&mut self.trace, part)?;
        validate_optional_empty_logprobs(&mut self.trace, part)?;
        validate_part(part, &self.text, false, &mut self.trace)?;
        self.stage = LifecycleStage::PartDone;
        Ok(())
    }
}
impl Lifecycle {
    fn accept_item_done(&mut self, event: &Map<String, Value>) -> Result<(), DeepSeekStreamError> {
        traced_exact_keys(
            &mut self.trace,
            event,
            &["item", "output_index", "sequence_number", "type"],
            DeepSeekDecodeSchemaNode::CompletedItem,
        )?;
        if self.stage != LifecycleStage::PartDone || required_u64(event, "output_index")? != 0 {
            return Err(DeepSeekStreamError::IllegalTransition);
        }
        let item = traced_required_object(
            &mut self.trace,
            event,
            "item",
            DeepSeekDecodeSchemaNode::CompletedItem,
        )?;
        traced_message_item_keys(
            &mut self.trace,
            item,
            DeepSeekDecodeSchemaNode::CompletedItem,
        )?;
        let item_id = self.item_id()?.to_owned();
        validate_completed_item(item, &item_id, &self.text, "completed", &mut self.trace)?;
        self.stage = LifecycleStage::ItemDone;
        Ok(())
    }
}
impl Lifecycle {
    fn accept_completed(&mut self, event: &Map<String, Value>) -> Result<(), DeepSeekStreamError> {
        traced_exact_keys(
            &mut self.trace,
            event,
            &["response", "sequence_number", "type"],
            DeepSeekDecodeSchemaNode::Response,
        )?;
        if self.stage != LifecycleStage::ItemDone {
            return Err(DeepSeekStreamError::IllegalTransition);
        }
        let response = traced_required_object(
            &mut self.trace,
            event,
            "response",
            DeepSeekDecodeSchemaNode::Response,
        )?;
        self.bind_response(response, "completed")?;
        validate_terminal_response_guards(response, false, false)?;
        let item_id = self.item_id()?.to_owned();
        validate_output(
            response,
            &item_id,
            &self.text,
            "completed",
            false,
            &mut self.trace,
        )?;
        let usage_value = response
            .get("usage")
            .filter(|value| !value.is_null())
            .ok_or(DeepSeekStreamError::InvalidUsage)?;
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
    fn accept_failed(&mut self, event: &Map<String, Value>) -> Result<(), DeepSeekStreamError> {
        traced_exact_keys(
            &mut self.trace,
            event,
            &["response", "sequence_number", "type"],
            DeepSeekDecodeSchemaNode::Response,
        )?;
        self.ensure_terminal_prefix_allowed()?;
        let response = traced_required_object(
            &mut self.trace,
            event,
            "response",
            DeepSeekDecodeSchemaNode::Response,
        )?;
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
    fn accept_incomplete(&mut self, event: &Map<String, Value>) -> Result<(), DeepSeekStreamError> {
        traced_exact_keys(
            &mut self.trace,
            event,
            &["response", "sequence_number", "type"],
            DeepSeekDecodeSchemaNode::Response,
        )?;
        self.ensure_terminal_prefix_allowed()?;
        let response = traced_required_object(
            &mut self.trace,
            event,
            "response",
            DeepSeekDecodeSchemaNode::Response,
        )?;
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
    fn accept_error(&mut self, event: &Map<String, Value>) -> Result<(), DeepSeekStreamError> {
        traced_exact_keys(
            &mut self.trace,
            event,
            &["code", "message", "param", "sequence_number", "type"],
            DeepSeekDecodeSchemaNode::ErrorEnvelope,
        )?;
        if self.stage != LifecycleStage::Start {
            return Err(DeepSeekStreamError::IllegalTransition);
        }
        validate_diagnostic_string(event, "code")?;
        validate_diagnostic_string(event, "message")?;
        if event.get("param").is_none() {
            return Err(DeepSeekStreamError::MalformedEvent);
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
    ) -> Result<(), DeepSeekStreamError> {
        validate_response_guards(response)?;
        let response_id = traced_required_string(
            &mut self.trace,
            response,
            "id",
            DeepSeekDecodeSchemaNode::Response,
        )?;
        validate_identifier(response_id)?;
        match self.response_id.as_deref() {
            Some(existing) if existing != response_id => {
                return Err(DeepSeekStreamError::CorrelationMismatch);
            }
            None => self.response_id = Some(response_id.to_owned()),
            Some(_) => {}
        }
        if required_string(response, "status")? != expected_status {
            return Err(DeepSeekStreamError::IllegalTransition);
        }
        Ok(())
    }
}
