fn validate_output(
    response: &Map<String, Value>,
    item_id: &str,
    text: &str,
    status: &str,
    allow_empty: bool,
) -> Result<(), OpenAiStreamError> {
    let output = response
        .get("output")
        .and_then(Value::as_array)
        .ok_or(OpenAiStreamError::MalformedEvent)?;
    if output.is_empty() && allow_empty {
        return Ok(());
    }
    if output.len() != 1 {
        return Err(OpenAiStreamError::CorrelationMismatch);
    }
    validate_completed_item(
        output[0]
            .as_object()
            .ok_or(OpenAiStreamError::MalformedEvent)?,
        item_id,
        text,
        status,
    )
}

fn parse_usage(value: &Value) -> Result<ProviderUsage, OpenAiStreamError> {
    let usage = value.as_object().ok_or(OpenAiStreamError::InvalidUsage)?;
    require_keys(
        usage,
        &[
            "input_tokens",
            "input_tokens_details",
            "output_tokens",
            "output_tokens_details",
            "total_tokens",
        ],
    )
    .map_err(|_| OpenAiStreamError::InvalidUsage)?;
    let input = required_u64(usage, "input_tokens").map_err(|_| OpenAiStreamError::InvalidUsage)?;
    let output =
        required_u64(usage, "output_tokens").map_err(|_| OpenAiStreamError::InvalidUsage)?;
    let total = required_u64(usage, "total_tokens").map_err(|_| OpenAiStreamError::InvalidUsage)?;
    if input.checked_add(output) != Some(total) {
        return Err(OpenAiStreamError::InvalidUsage);
    }
    let input_details = required_object(usage, "input_tokens_details")
        .map_err(|_| OpenAiStreamError::InvalidUsage)?;
    require_keys(input_details, &["cached_tokens"]).map_err(|_| OpenAiStreamError::InvalidUsage)?;
    let cached = required_u64(input_details, "cached_tokens")
        .map_err(|_| OpenAiStreamError::InvalidUsage)?;
    let output_details = required_object(usage, "output_tokens_details")
        .map_err(|_| OpenAiStreamError::InvalidUsage)?;
    require_keys(output_details, &["reasoning_tokens"])
        .map_err(|_| OpenAiStreamError::InvalidUsage)?;
    let reasoning = required_u64(output_details, "reasoning_tokens")
        .map_err(|_| OpenAiStreamError::InvalidUsage)?;
    ProviderUsage::new(input, output, cached, reasoning)
        .map_err(|_| OpenAiStreamError::InvalidUsage)
}

fn validate_identifier(value: &str) -> Result<(), OpenAiStreamError> {
    if value.is_empty()
        || value.len() > MAX_REMOTE_IDENTIFIER_BYTES
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(OpenAiStreamError::CorrelationMismatch);
    }
    Ok(())
}

fn validate_diagnostic_string(
    object: &Map<String, Value>,
    key: &str,
) -> Result<(), OpenAiStreamError> {
    let value = object.get(key).ok_or(OpenAiStreamError::MalformedEvent)?;
    validate_bounded_string(value)
}

fn validate_bounded_string(value: &Value) -> Result<(), OpenAiStreamError> {
    let value = value.as_str().ok_or(OpenAiStreamError::MalformedEvent)?;
    if value.is_empty() || value.len() > MAX_REMOTE_DIAGNOSTIC_BYTES {
        return Err(OpenAiStreamError::StreamLimitExceeded);
    }
    Ok(())
}

fn validate_empty_logprobs(event: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
    if event
        .get("logprobs")
        .is_some_and(|value| value.as_array().is_none_or(|values| !values.is_empty()))
    {
        return Err(OpenAiStreamError::UnknownEvent);
    }
    Ok(())
}

fn require_empty_output(response: &Map<String, Value>) -> Result<(), OpenAiStreamError> {
    if !response
        .get("output")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
    {
        return Err(OpenAiStreamError::UnknownEvent);
    }
    Ok(())
}

fn require_null_or_missing(
    object: &Map<String, Value>,
    key: &str,
) -> Result<(), OpenAiStreamError> {
    if object.get(key).is_some_and(|value| !value.is_null()) {
        return Err(OpenAiStreamError::IllegalTransition);
    }
    Ok(())
}

fn required_object<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Map<String, Value>, OpenAiStreamError> {
    object
        .get(key)
        .and_then(Value::as_object)
        .ok_or(OpenAiStreamError::MalformedEvent)
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, OpenAiStreamError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(OpenAiStreamError::MalformedEvent)
}

fn required_u64(object: &Map<String, Value>, key: &str) -> Result<u64, OpenAiStreamError> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(OpenAiStreamError::MalformedEvent)
}

fn require_keys(object: &Map<String, Value>, exact: &[&str]) -> Result<(), OpenAiStreamError> {
    let expected = exact.iter().copied().collect::<BTreeSet<_>>();
    let actual = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(OpenAiStreamError::MalformedEvent);
    }
    Ok(())
}

fn require_keys_subset(
    object: &Map<String, Value>,
    allowed: &[&str],
    required: &[&str],
) -> Result<(), OpenAiStreamError> {
    if !object.keys().all(|key| allowed.contains(&key.as_str()))
        || !required.iter().all(|key| object.contains_key(*key))
    {
        return Err(OpenAiStreamError::MalformedEvent);
    }
    Ok(())
}
