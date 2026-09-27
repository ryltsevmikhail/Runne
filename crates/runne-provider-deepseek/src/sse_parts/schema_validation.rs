fn validate_added_item(
    item: &Map<String, Value>,
    trace: &mut DecodeTrace,
) -> Result<(), DeepSeekStreamError> {
    traced_exact_keys(
        trace,
        item,
        &["content", "id", "role", "status", "type"],
        DeepSeekDecodeSchemaNode::AddedItem,
    )?;
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
    traced_exact_keys(
        trace,
        item,
        &["content", "id", "role", "status", "type"],
        DeepSeekDecodeSchemaNode::CompletedItem,
    )?;
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
    traced_exact_keys(
        trace,
        part,
        &["annotations", "text", "type"],
        DeepSeekDecodeSchemaNode::OutputTextPart,
    )?;
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
    traced_exact_keys(
        trace,
        item,
        &["content", "id", "role", "status", "type"],
        DeepSeekDecodeSchemaNode::CompletedItem,
    )?;
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
    traced_exact_keys(
        trace,
        part,
        &["annotations", "text", "type"],
        DeepSeekDecodeSchemaNode::OutputTextPart,
    )?;
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
