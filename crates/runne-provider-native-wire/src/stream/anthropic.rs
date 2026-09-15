use runne_provider::{
    ProviderFinishReason, ProviderStreamEventKind, ProviderTerminalDisposition, ProviderUsage,
};
use serde_json::{Map, Value};

use super::common::{BlockKind, Stage, State, WireDecodeError};
use crate::sse::SseFrame;

pub(super) fn accept(state: &mut State, frame: SseFrame) -> Result<(), WireDecodeError> {
    let event = frame.event.ok_or(WireDecodeError::Malformed)?;
    let value: Value =
        serde_json::from_slice(&frame.data).map_err(|_| WireDecodeError::Malformed)?;
    let object = value.as_object().ok_or(WireDecodeError::Malformed)?;
    if object.get("type").and_then(Value::as_str) != Some(event.as_str()) {
        return Err(WireDecodeError::Malformed);
    }
    if state.terminal {
        return Err(WireDecodeError::Malformed);
    }
    match event.as_str() {
        "ping" => ping(object),
        "message_start" => message_start(state, object),
        "content_block_start" => block_start(state, object),
        "content_block_delta" => block_delta(state, object),
        "content_block_stop" => block_stop(state, object),
        "message_delta" => message_delta(state, object),
        "message_stop" => message_stop(state),
        _ => Err(WireDecodeError::Malformed),
    }
}

fn ping(object: &Map<String, Value>) -> Result<(), WireDecodeError> {
    if object.len() == 1 && object.get("type").and_then(Value::as_str) == Some("ping") {
        Ok(())
    } else {
        Err(WireDecodeError::Malformed)
    }
}

fn message_start(state: &mut State, object: &Map<String, Value>) -> Result<(), WireDecodeError> {
    if state.stage != Stage::Start {
        return Err(WireDecodeError::Malformed);
    }
    let message = object
        .get("message")
        .and_then(Value::as_object)
        .ok_or(WireDecodeError::Malformed)?;
    if message.get("type").and_then(Value::as_str) != Some("message")
        || message.get("role").and_then(Value::as_str) != Some("assistant")
    {
        return Err(WireDecodeError::Malformed);
    }
    let model = message
        .get("model")
        .and_then(Value::as_str)
        .ok_or(WireDecodeError::Malformed)?;
    if state
        .model
        .as_deref()
        .is_some_and(|expected| expected != model)
    {
        return Err(WireDecodeError::Malformed);
    }
    let id = message
        .get("id")
        .and_then(Value::as_str)
        .ok_or(WireDecodeError::Malformed)?;
    state.response_id = Some(id.to_owned());
    let usage = message
        .get("usage")
        .and_then(Value::as_object)
        .ok_or(WireDecodeError::InvalidUsage)?;
    let input = required_u64(usage, "input_tokens")?;
    let cached = optional_u64(usage, "cache_read_input_tokens")?;
    if optional_u64(usage, "cache_creation_input_tokens")? != 0 {
        return Err(WireDecodeError::UnsupportedContent);
    }
    let output = optional_u64(usage, "output_tokens")?;
    state.usage = Some(
        ProviderUsage::new(
            input
                .checked_add(cached)
                .ok_or(WireDecodeError::InvalidUsage)?,
            output,
            cached,
            0,
        )
        .map_err(|_| WireDecodeError::InvalidUsage)?,
    );
    state.push_event(ProviderStreamEventKind::Started)?;
    state.stage = Stage::Block;
    Ok(())
}

fn block_start(state: &mut State, object: &Map<String, Value>) -> Result<(), WireDecodeError> {
    if state.stage != Stage::Block || state.active_block.is_some() {
        return Err(WireDecodeError::Malformed);
    }
    let index = index(object)?;
    if index != state.next_block_index {
        return Err(WireDecodeError::Malformed);
    }
    let block = object
        .get("content_block")
        .and_then(Value::as_object)
        .ok_or(WireDecodeError::Malformed)?;
    let kind = match block.get("type").and_then(Value::as_str) {
        Some("text") if block.get("text").and_then(Value::as_str).is_some() => BlockKind::Text,
        Some("thinking") if block.get("thinking").and_then(Value::as_str).is_some() => {
            BlockKind::Thinking
        }
        Some("redacted_thinking") if block.get("data").and_then(Value::as_str).is_some() => {
            BlockKind::Thinking
        }
        Some("text" | "thinking" | "redacted_thinking") => {
            return Err(WireDecodeError::Malformed);
        }
        _ => return Err(WireDecodeError::UnsupportedContent),
    };
    state.active_block = Some(kind);
    state.stage = Stage::Delta;
    Ok(())
}

fn block_delta(state: &mut State, object: &Map<String, Value>) -> Result<(), WireDecodeError> {
    if state.stage != Stage::Delta || index(object)? != state.next_block_index {
        return Err(WireDecodeError::Malformed);
    }
    let delta = object
        .get("delta")
        .and_then(Value::as_object)
        .ok_or(WireDecodeError::Malformed)?;
    match (
        state.active_block,
        delta.get("type").and_then(Value::as_str),
    ) {
        (Some(BlockKind::Text), Some("text_delta")) => state.text(
            delta
                .get("text")
                .and_then(Value::as_str)
                .ok_or(WireDecodeError::Malformed)?,
        ),
        (Some(BlockKind::Thinking), Some("thinking_delta")) => delta
            .get("thinking")
            .and_then(Value::as_str)
            .map(|_| ())
            .ok_or(WireDecodeError::Malformed),
        (Some(BlockKind::Thinking), Some("signature_delta")) => delta
            .get("signature")
            .and_then(Value::as_str)
            .map(|_| ())
            .ok_or(WireDecodeError::Malformed),
        _ => Err(WireDecodeError::UnsupportedContent),
    }
}

fn block_stop(state: &mut State, object: &Map<String, Value>) -> Result<(), WireDecodeError> {
    if state.stage != Stage::Delta || index(object)? != state.next_block_index {
        return Err(WireDecodeError::Malformed);
    }
    state.active_block = None;
    state.next_block_index = state
        .next_block_index
        .checked_add(1)
        .ok_or(WireDecodeError::BoundExceeded)?;
    state.stage = Stage::Block;
    Ok(())
}

fn message_delta(state: &mut State, object: &Map<String, Value>) -> Result<(), WireDecodeError> {
    if state.stage != Stage::Block || state.active_block.is_some() || state.stop.is_some() {
        return Err(WireDecodeError::Malformed);
    }
    let delta = object
        .get("delta")
        .and_then(Value::as_object)
        .ok_or(WireDecodeError::Malformed)?;
    let reason = delta
        .get("stop_reason")
        .and_then(Value::as_str)
        .ok_or(WireDecodeError::Malformed)?;
    let usage = object
        .get("usage")
        .and_then(Value::as_object)
        .ok_or(WireDecodeError::InvalidUsage)?;
    let base = state.usage.ok_or(WireDecodeError::InvalidUsage)?;
    let output = optional_u64(usage, "output_tokens")?;
    if optional_u64(usage, "cache_creation_input_tokens")? != 0 {
        return Err(WireDecodeError::UnsupportedContent);
    }
    if output < base.output_tokens() {
        return Err(WireDecodeError::InvalidUsage);
    }
    let input = optional_u64(usage, "input_tokens")?.max(base.input_tokens());
    let cached = optional_u64(usage, "cache_read_input_tokens")?.max(base.cached_input_tokens());
    if cached > input {
        return Err(WireDecodeError::InvalidUsage);
    }
    let reasoning = usage
        .get("output_tokens_details")
        .and_then(Value::as_object)
        .map_or(Ok(0), |details| optional_u64(details, "thinking_tokens"))?;
    if reasoning > output {
        return Err(WireDecodeError::InvalidUsage);
    }
    state.usage = Some(
        ProviderUsage::new(input, output, cached, reasoning)
            .map_err(|_| WireDecodeError::InvalidUsage)?,
    );
    state.stop = Some(stop_reason(reason)?);
    state.push_event(ProviderStreamEventKind::Usage {
        usage: state.usage.ok_or(WireDecodeError::InvalidUsage)?,
    })
}

fn message_stop(state: &mut State) -> Result<(), WireDecodeError> {
    if state.stage != Stage::Block || state.active_block.is_some() || state.stop.is_none() {
        return Err(WireDecodeError::Malformed);
    }
    let (disposition, reason) = state.stop.clone().ok_or(WireDecodeError::Malformed)?;
    state.push_event(ProviderStreamEventKind::Finished {
        disposition,
        reason,
    })?;
    state.stage = Stage::Terminal;
    state.terminal = true;
    Ok(())
}

fn required_u64(object: &Map<String, Value>, key: &str) -> Result<u64, WireDecodeError> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(WireDecodeError::InvalidUsage)
}
fn optional_u64(object: &Map<String, Value>, key: &str) -> Result<u64, WireDecodeError> {
    object.get(key).map_or(Ok(0), |value| {
        value.as_u64().ok_or(WireDecodeError::InvalidUsage)
    })
}
fn index(object: &Map<String, Value>) -> Result<u64, WireDecodeError> {
    object
        .get("index")
        .and_then(Value::as_u64)
        .ok_or(WireDecodeError::Malformed)
}
fn stop_reason(
    reason: &str,
) -> Result<(ProviderTerminalDisposition, ProviderFinishReason), WireDecodeError> {
    match reason {
        "end_turn" | "stop_sequence" => Ok((
            ProviderTerminalDisposition::Completed,
            ProviderFinishReason::Stop,
        )),
        "max_tokens" => Ok((
            ProviderTerminalDisposition::RemoteIncomplete,
            ProviderFinishReason::Length,
        )),
        "refusal" => Ok((
            ProviderTerminalDisposition::RemoteFailed,
            ProviderFinishReason::Error,
        )),
        "tool_use" => Err(WireDecodeError::UnsupportedContent),
        _ => Err(WireDecodeError::Malformed),
    }
}
