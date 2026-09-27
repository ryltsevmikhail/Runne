impl Lifecycle {
    fn validate_item_indexes(&self, event: &Map<String, Value>) -> Result<(), DeepSeekStreamError> {
        if required_u64(event, "output_index")? != 0
            || required_u64(event, "content_index")? != 0
            || required_string(event, "item_id")? != self.item_id()?
        {
            return Err(DeepSeekStreamError::CorrelationMismatch);
        }
        Ok(())
    }
}
impl Lifecycle {
    fn accept_optional_terminal_output(
        &mut self,
        response: &Map<String, Value>,
        allowed_statuses: &[&str],
    ) -> Result<(), DeepSeekStreamError> {
        let output = response
            .get("output")
            .and_then(Value::as_array)
            .ok_or(DeepSeekStreamError::MalformedEvent)?;
        if output.is_empty() {
            return Ok(());
        }
        let item = output
            .first()
            .and_then(Value::as_object)
            .ok_or(DeepSeekStreamError::MalformedEvent)?;
        if output.len() != 1 {
            return Err(DeepSeekStreamError::CorrelationMismatch);
        }
        let status = required_string(item, "status")?;
        if !allowed_statuses.contains(&status) {
            return Err(DeepSeekStreamError::IllegalTransition);
        }
        if self.item_id.is_none() {
            let item_id = required_string(item, "id")?;
            validate_identifier(item_id)?;
            let text = terminal_item_text(item, status, &mut self.trace)?;
            let next = self
                .text
                .len()
                .checked_add(text.len())
                .filter(|length| *length <= DEEPSEEK_MAX_NORMALIZED_TEXT_BYTES)
                .ok_or(DeepSeekStreamError::StreamLimitExceeded)?;
            if !self.text.is_empty() {
                return Err(DeepSeekStreamError::CorrelationMismatch);
            }
            self.text.reserve(next);
            self.text.push_str(text);
            self.item_id = Some(item_id.to_owned());
            if !text.is_empty() {
                self.push_normalized(ProviderStreamEventKind::TextDelta {
                    text: text.to_owned(),
                })?;
            }
        }
        let item_id = self.item_id()?.to_owned();
        validate_completed_item(item, &item_id, &self.text, status, &mut self.trace)
    }
}
impl Lifecycle {
    fn push_optional_usage(
        &mut self,
        response: &Map<String, Value>,
    ) -> Result<(), DeepSeekStreamError> {
        match response.get("usage") {
            Some(value) if !value.is_null() => {
                let usage = parse_usage(value)?;
                self.push_normalized(ProviderStreamEventKind::Usage { usage })
            }
            Some(_) | None => self.push_normalized(ProviderStreamEventKind::UsageUnavailable),
        }
    }
}
impl Lifecycle {
    fn ensure_terminal_prefix_allowed(&mut self) -> Result<(), DeepSeekStreamError> {
        self.ensure_started()
    }
}
impl Lifecycle {
    fn ensure_started(&mut self) -> Result<(), DeepSeekStreamError> {
        if self.normalized.is_empty() {
            self.push_normalized(ProviderStreamEventKind::Started)?;
        }
        Ok(())
    }
}
impl Lifecycle {
    fn push_normalized(
        &mut self,
        kind: ProviderStreamEventKind,
    ) -> Result<(), DeepSeekStreamError> {
        let sequence = u64::try_from(self.normalized.len())
            .map_err(|_| DeepSeekStreamError::StreamLimitExceeded)?;
        let event = ProviderStreamEvent::new(sequence, kind)
            .map_err(|_| DeepSeekStreamError::MalformedEvent)?;
        self.normalized.push(event);
        Ok(())
    }
}
impl Lifecycle {
    fn item_id(&self) -> Result<&str, DeepSeekStreamError> {
        self.item_id
            .as_deref()
            .ok_or(DeepSeekStreamError::CorrelationMismatch)
    }
}
pub fn validate_remote_rejection(body: &[u8]) -> Result<(), DeepSeekStreamError> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| DeepSeekStreamError::MalformedEvent)?;
    let root = value
        .as_object()
        .ok_or(DeepSeekStreamError::MalformedEvent)?;
    require_keys(root, &["error"])?;
    let error = required_object(root, "error")?;
    let allowed = ["code", "message", "param", "type"];
    if !error.keys().all(|key| allowed.contains(&key.as_str())) {
        return Err(DeepSeekStreamError::MalformedEvent);
    }
    validate_diagnostic_string(error, "message")?;
    if let Some(value) = error.get("type") {
        validate_bounded_string(value)?;
    }
    if let Some(value) = error.get("code") {
        validate_bounded_string(value)?;
    }
    Ok(())
}
fn validate_response_guards(response: &Map<String, Value>) -> Result<(), DeepSeekStreamError> {
    if response.get("object").and_then(Value::as_str) != Some("response")
        || response.get("model").and_then(Value::as_str) != Some(DEEPSEEK_REQUEST_MODEL)
    {
        return Err(DeepSeekStreamError::CorrelationMismatch);
    }
    if response
        .get("background")
        .is_some_and(|value| value != false)
        || response.get("store").is_some_and(|value| value != false)
        || response
            .get("tools")
            .is_some_and(|value| value.as_array().is_none_or(|tools| !tools.is_empty()))
    {
        return Err(DeepSeekStreamError::UnknownEvent);
    }
    Ok(())
}

fn validate_terminal_response_guards(
    response: &Map<String, Value>,
    requires_error: bool,
    requires_incomplete_details: bool,
) -> Result<(), DeepSeekStreamError> {
    let error_present = response.get("error").is_some_and(|value| !value.is_null());
    let incomplete_present = response
        .get("incomplete_details")
        .is_some_and(|value| !value.is_null());
    if error_present != requires_error || incomplete_present != requires_incomplete_details {
        return Err(DeepSeekStreamError::IllegalTransition);
    }
    if requires_error {
        let error = required_object(response, "error")?;
        validate_diagnostic_string(error, "code")?;
        validate_diagnostic_string(error, "message")?;
    }
    if requires_incomplete_details {
        let details = required_object(response, "incomplete_details")?;
        require_keys(details, &["reason"])?;
        validate_diagnostic_string(details, "reason")?;
    }
    Ok(())
}
