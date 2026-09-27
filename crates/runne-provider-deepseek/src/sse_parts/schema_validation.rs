fn validate_added_item(
    item: &Map<String, Value>,
    trace: &mut DecodeTrace,
) -> Result<(), DeepSeekStreamError> {
    traced_message_item_keys(trace, item, DeepSeekDecodeSchemaNode::AddedItem)?;
    validate_optional_message_phase(trace, item, DeepSeekDecodeSchemaNode::AddedItem)?;
    if required_string(item, "type")? != "message"
        || required_string(item, "status")? != "in_progress"
        || required_string(item, "role")? != "assistant"
        || !traced_array_is_empty(trace, item, "content", DeepSeekDecodeSchemaNode::AddedItem)
    {
        return Err(DeepSeekStreamError::UnknownEvent);
    }
    Ok(())
}

fn terminal_item_text<'a>(
    item: &'a Map<String, Value>,
    status: &str,
    trace: &mut DecodeTrace,
) -> Result<&'a str, DeepSeekStreamError> {
    traced_message_item_keys(trace, item, DeepSeekDecodeSchemaNode::CompletedItem)?;
    validate_optional_message_phase(trace, item, DeepSeekDecodeSchemaNode::CompletedItem)?;
    if required_string(item, "type")? != "message"
        || required_string(item, "status")? != status
        || required_string(item, "role")? != "assistant"
    {
        return Err(DeepSeekStreamError::UnknownEvent);
    }
    let content = traced_required_array(
        trace,
        item,
        "content",
        DeepSeekDecodeSchemaNode::CompletedItem,
    )?;
    if content.len() != 1 {
        return Err(DeepSeekStreamError::UnknownEvent);
    }
    let part = content[0]
        .as_object()
        .ok_or(DeepSeekStreamError::MalformedEvent)?;
    traced_output_text_part_keys(trace, part)?;
    validate_optional_empty_logprobs(trace, part)?;
    if required_string(part, "type")? != "output_text"
        || !traced_array_is_empty(
            trace,
            part,
            "annotations",
            DeepSeekDecodeSchemaNode::OutputTextPart,
        )
    {
        return Err(DeepSeekStreamError::UnknownEvent);
    }
    required_string(part, "text")
}

fn validate_completed_item(
    item: &Map<String, Value>,
    item_id: &str,
    text: &str,
    status: &str,
    trace: &mut DecodeTrace,
) -> Result<(), DeepSeekStreamError> {
    traced_message_item_keys(trace, item, DeepSeekDecodeSchemaNode::CompletedItem)?;
    validate_optional_message_phase(trace, item, DeepSeekDecodeSchemaNode::CompletedItem)?;
    if required_string(item, "id")? != item_id
        || required_string(item, "type")? != "message"
        || required_string(item, "status")? != status
        || required_string(item, "role")? != "assistant"
    {
        return Err(DeepSeekStreamError::CorrelationMismatch);
    }
    let content = traced_required_array(
        trace,
        item,
        "content",
        DeepSeekDecodeSchemaNode::CompletedItem,
    )?;
    if content.len() != 1 {
        return Err(DeepSeekStreamError::UnknownEvent);
    }
    validate_part(
        content[0]
            .as_object()
            .ok_or(DeepSeekStreamError::MalformedEvent)?,
        text,
        false,
        trace,
    )
}

fn validate_part(
    part: &Map<String, Value>,
    text: &str,
    added: bool,
    trace: &mut DecodeTrace,
) -> Result<(), DeepSeekStreamError> {
    traced_output_text_part_keys(trace, part)?;
    validate_optional_empty_logprobs(trace, part)?;
    if required_string(part, "type")? != "output_text"
        || required_string(part, "text")? != text
        || !traced_array_is_empty(
            trace,
            part,
            "annotations",
            DeepSeekDecodeSchemaNode::OutputTextPart,
        )
        || (added && !text.is_empty())
    {
        return Err(DeepSeekStreamError::UnknownEvent);
    }
    Ok(())
}

fn validate_optional_message_phase(
    trace: &mut DecodeTrace,
    object: &Map<String, Value>,
    node: DeepSeekDecodeSchemaNode,
) -> Result<(), DeepSeekStreamError> {
    let Some(value) = object.get("phase") else {
        return Ok(());
    };
    if object.get("type").and_then(Value::as_str) != Some("message") {
        trace.record(
            DeepSeekDecodePhase::EventSchema,
            node,
            DeepSeekDecodeField::Phase,
            DeepSeekDecodeIssue::ValueMismatch,
        );
        return Err(DeepSeekStreamError::MalformedEvent);
    }
    if value.is_null() || matches!(value.as_str(), Some("commentary" | "final_answer")) {
        return Ok(());
    }
    trace.record(
        DeepSeekDecodePhase::EventSchema,
        node,
        DeepSeekDecodeField::Phase,
        if value.is_string() {
            DeepSeekDecodeIssue::ValueMismatch
        } else {
            DeepSeekDecodeIssue::WrongType
        },
    );
    Err(DeepSeekStreamError::MalformedEvent)
}

fn validate_optional_empty_logprobs(
    trace: &mut DecodeTrace,
    object: &Map<String, Value>,
) -> Result<(), DeepSeekStreamError> {
    let Some(value) = object.get("logprobs") else {
        return Ok(());
    };
    if object.get("type").and_then(Value::as_str) != Some("output_text") {
        trace.record(
            DeepSeekDecodePhase::EventSchema,
            DeepSeekDecodeSchemaNode::OutputTextPart,
            DeepSeekDecodeField::Logprobs,
            DeepSeekDecodeIssue::ValueMismatch,
        );
        return Err(DeepSeekStreamError::MalformedEvent);
    }
    if value.is_null() {
        return Ok(());
    }
    let Some(values) = value.as_array() else {
        trace.record(
            DeepSeekDecodePhase::EventSchema,
            DeepSeekDecodeSchemaNode::OutputTextPart,
            DeepSeekDecodeField::Logprobs,
            DeepSeekDecodeIssue::WrongType,
        );
        return Err(DeepSeekStreamError::MalformedEvent);
    };
    if values.is_empty() {
        return Ok(());
    }
    trace.record(
        DeepSeekDecodePhase::EventSchema,
        DeepSeekDecodeSchemaNode::OutputTextPart,
        DeepSeekDecodeField::Logprobs,
        DeepSeekDecodeIssue::ValueMismatch,
    );
    Err(DeepSeekStreamError::MalformedEvent)
}
