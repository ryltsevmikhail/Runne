fn parse_value(bytes: &[u8]) -> Result<Value, OpenAiStreamError> {
    if bytes.is_empty() || bytes.len() > OPENAI_MAX_BACKGROUND_STATUS_BYTES {
        return Err(OpenAiStreamError::StreamLimitExceeded);
    }
    serde_json::from_slice(bytes).map_err(|_| OpenAiStreamError::MalformedEvent)
}

fn openai_response_id(object: &Map<String, Value>) -> Result<RemoteResponseId, OpenAiStreamError> {
    let value = string_field(object, "id")?;
    validate_openai_response_id(value)?;
    RemoteResponseId::new(value).map_err(|_| OpenAiStreamError::CorrelationMismatch)
}

fn validate_openai_response_id(value: &str) -> Result<(), OpenAiStreamError> {
    let Some(suffix) = value.strip_prefix("resp_") else {
        return Err(OpenAiStreamError::CorrelationMismatch);
    };
    if suffix.is_empty()
        || value.len() > RemoteResponseId::MAX_BYTES
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(OpenAiStreamError::CorrelationMismatch);
    }
    Ok(())
}

fn validate_profile_guards(
    object: &Map<String, Value>,
    profile: &OpenAiResponsesTextProfile,
) -> Result<(), OpenAiStreamError> {
    if string_field(object, "object")? != "response"
        || string_field(object, "model")? != profile.request_model()
        || string_field(object, "service_tier")? != profile.service_tier()
        || object.get("background") != Some(&Value::Bool(true))
        || object.get("store") != Some(&Value::Bool(false))
    {
        return Err(OpenAiStreamError::CorrelationMismatch);
    }
    if object
        .get("tools")
        .is_some_and(|value| value.as_array().is_none_or(|tools| !tools.is_empty()))
    {
        return Err(OpenAiStreamError::UnknownEvent);
    }
    Ok(())
}

fn validate_terminal_fields(
    object: &Map<String, Value>,
    status: &str,
) -> Result<(), OpenAiStreamError> {
    match status {
        "completed" | "cancelled" => {
            require_null_or_missing(object, "error")?;
            require_null_or_missing(object, "incomplete_details")?;
            optional_usage(object)?;
        }
        "failed" => {
            let error = object
                .get("error")
                .and_then(Value::as_object)
                .ok_or(OpenAiStreamError::MalformedEvent)?;
            bounded_string(error, "code")?;
            bounded_string(error, "message")?;
            require_null_or_missing(object, "incomplete_details")?;
            optional_usage(object)?;
        }
        "incomplete" => {
            require_null_or_missing(object, "error")?;
            let details = object
                .get("incomplete_details")
                .and_then(Value::as_object)
                .ok_or(OpenAiStreamError::MalformedEvent)?;
            bounded_string(details, "reason")?;
            optional_usage(object)?;
        }
        _ => return Err(OpenAiStreamError::TerminalMissing),
    }
    Ok(())
}

fn validate_terminal_output(
    object: &Map<String, Value>,
    status: &str,
) -> Result<Option<String>, OpenAiStreamError> {
    let output = object
        .get("output")
        .and_then(Value::as_array)
        .ok_or(OpenAiStreamError::MalformedEvent)?;
    if output.is_empty() {
        return if status == "completed" {
            Err(OpenAiStreamError::MalformedEvent)
        } else {
            Ok(None)
        };
    }
    if output.len() != 1 {
        return Err(OpenAiStreamError::UnknownEvent);
    }
    let item = output[0]
        .as_object()
        .ok_or(OpenAiStreamError::MalformedEvent)?;
    let item_id = string_field(item, "id")?;
    crate::sse::validate_identifier(item_id)?;
    let item_status = string_field(item, "status")?;
    if !["in_progress", "completed", "incomplete"].contains(&item_status) {
        return Err(OpenAiStreamError::UnknownEvent);
    }
    if status == "completed" && item_status != "completed" {
        return Err(OpenAiStreamError::IllegalTransition);
    }
    let text = crate::sse::terminal_item_text(item, item_status)?;
    if text.len() > OPENAI_MAX_BACKGROUND_TEXT_BYTES {
        return Err(OpenAiStreamError::StreamLimitExceeded);
    }
    Ok(Some(text.to_owned()))
}

fn remote_status(
    object: &Map<String, Value>,
) -> Result<ProviderRemoteResponseStatus, OpenAiStreamError> {
    let usage = optional_usage(object)?;
    Ok(match object.get("status").and_then(Value::as_str) {
        Some("queued" | "in_progress") => ProviderRemoteResponseStatus::Pending,
        Some("completed") => ProviderRemoteResponseStatus::Completed { usage },
        Some("failed") => ProviderRemoteResponseStatus::Failed {
            code: optional_nested_string(object.get("error"), "code")?,
            usage,
        },
        Some("incomplete") => ProviderRemoteResponseStatus::Incomplete {
            reason: optional_nested_string(object.get("incomplete_details"), "reason")?,
            usage,
        },
        Some("cancelled") => ProviderRemoteResponseStatus::Cancelled { usage },
        _ => ProviderRemoteResponseStatus::Unknown,
    })
}

fn optional_usage(object: &Map<String, Value>) -> Result<Option<ProviderUsage>, OpenAiStreamError> {
    object
        .get("usage")
        .filter(|value| !value.is_null())
        .map(crate::sse::parse_usage)
        .transpose()
}

fn optional_nested_string(
    value: Option<&Value>,
    key: &str,
) -> Result<Option<String>, OpenAiStreamError> {
    let Some(value) = value else { return Ok(None) };
    let object = value.as_object().ok_or(OpenAiStreamError::MalformedEvent)?;
    if !object.contains_key(key) {
        return Ok(None);
    }
    bounded_string(object, key).map(Some)
}

fn bounded_string(object: &Map<String, Value>, key: &str) -> Result<String, OpenAiStreamError> {
    let text = object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(OpenAiStreamError::MalformedEvent)?;
    if text.is_empty() || text.len() > 4096 || text.chars().any(char::is_control) {
        return Err(OpenAiStreamError::StreamLimitExceeded);
    }
    Ok(text.to_owned())
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

fn string_field<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, OpenAiStreamError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(OpenAiStreamError::MalformedEvent)
}
