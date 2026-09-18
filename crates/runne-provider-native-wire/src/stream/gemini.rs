use runne_provider::{
    ProviderFinishReason, ProviderStreamEventKind, ProviderTerminalDisposition, ProviderUsage,
};
use serde_json::{Map, Value};

use super::common::{Stage, State, WireDecodeError};
use crate::sse::SseFrame;

pub(super) fn accept(state: &mut State, frame: SseFrame) -> Result<(), WireDecodeError> {
    if frame.event.is_some() {
        return Err(WireDecodeError::Malformed);
    }
    let value: Value =
        serde_json::from_slice(&frame.data).map_err(|_| WireDecodeError::Malformed)?;
    let root = value.as_object().ok_or(WireDecodeError::Malformed)?;
    if let Some(reported) = root.get("modelVersion").and_then(Value::as_str) {
        let accepted = state.model.as_deref() == Some(reported)
            || state.model_alias.as_deref() == Some(reported);
        if !accepted {
            return Err(WireDecodeError::Malformed);
        }
    }
    if let Some(id) = root.get("responseId").and_then(Value::as_str)
        && state
            .response_id
            .replace(id.to_owned())
            .is_some_and(|old| old != id)
    {
        return Err(WireDecodeError::Malformed);
    }
    if state.terminal {
        return Err(WireDecodeError::Malformed);
    }
    if state.stage == Stage::Start {
        state.push_event(ProviderStreamEventKind::Started)?;
        state.stage = Stage::Delta;
    }
    accept_parts(state, root)?;
    accept_usage(state, root)?;
    if let Some(reason) = finish_reason(root)? {
        if state.stop.is_some() {
            return Err(WireDecodeError::Malformed);
        }
        state.stop = Some(stop_reason(reason)?);
        let usage = state.usage.ok_or(WireDecodeError::InvalidUsage)?;
        state.push_event(ProviderStreamEventKind::Usage { usage })?;
        let (disposition, normalized) = state.stop.clone().ok_or(WireDecodeError::Malformed)?;
        state.push_event(ProviderStreamEventKind::Finished {
            disposition,
            reason: normalized,
        })?;
        state.terminal = true;
    }
    Ok(())
}

fn accept_parts(state: &mut State, root: &Map<String, Value>) -> Result<(), WireDecodeError> {
    let candidates = root
        .get("candidates")
        .and_then(Value::as_array)
        .ok_or(WireDecodeError::Malformed)?;
    if candidates.len() != 1 {
        return Err(WireDecodeError::Malformed);
    }
    if candidates[0].get("index").and_then(Value::as_u64) != Some(0) {
        return Err(WireDecodeError::Malformed);
    }
    if let Some(parts) = candidates[0]
        .get("content")
        .and_then(|value| value.get("parts"))
        .and_then(Value::as_array)
    {
        for part in parts {
            if part.get("functionCall").is_some()
                || part.get("inlineData").is_some()
                || part.get("fileData").is_some()
            {
                return Err(WireDecodeError::UnsupportedContent);
            }
            if let Some(text) = part.get("text").and_then(Value::as_str) {
                if part.get("thought").and_then(Value::as_bool) != Some(true) {
                    state.text(text)?;
                }
            } else {
                return Err(WireDecodeError::UnsupportedContent);
            }
        }
    }
    Ok(())
}

fn accept_usage(state: &mut State, root: &Map<String, Value>) -> Result<(), WireDecodeError> {
    let Some(value) = root.get("usageMetadata") else {
        return Ok(());
    };
    let usage = value.as_object().ok_or(WireDecodeError::InvalidUsage)?;
    let previous = state.usage_parts;
    let input = required_component(usage, "promptTokenCount", previous.map(|parts| parts.0))?;
    let cached = cumulative_component(
        usage,
        "cachedContentTokenCount",
        previous.map(|parts| parts.1),
    )?;
    let candidates =
        required_component(usage, "candidatesTokenCount", previous.map(|parts| parts.2))?;
    let reasoning =
        cumulative_component(usage, "thoughtsTokenCount", previous.map(|parts| parts.3))?;
    if let Some((old_input, old_cached, old_candidates, old_reasoning)) = previous
        && (input < old_input
            || cached < old_cached
            || candidates < old_candidates
            || reasoning < old_reasoning)
    {
        return Err(WireDecodeError::InvalidUsage);
    }
    let output = candidates
        .checked_add(reasoning)
        .ok_or(WireDecodeError::InvalidUsage)?;
    let total = usage.get("totalTokenCount").map_or_else(
        || {
            input
                .checked_add(output)
                .ok_or(WireDecodeError::InvalidUsage)
        },
        |value| value.as_u64().ok_or(WireDecodeError::InvalidUsage),
    )?;
    if total
        != input
            .checked_add(output)
            .ok_or(WireDecodeError::InvalidUsage)?
    {
        return Err(WireDecodeError::InvalidUsage);
    }
    state.usage_parts = Some((input, cached, candidates, reasoning));
    state.usage = Some(
        ProviderUsage::new(input, output, cached, reasoning)
            .map_err(|_| WireDecodeError::InvalidUsage)?,
    );
    Ok(())
}

fn required_component(
    object: &Map<String, Value>,
    key: &str,
    previous: Option<u64>,
) -> Result<u64, WireDecodeError> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .or(previous)
        .ok_or(WireDecodeError::InvalidUsage)
}
fn cumulative_component(
    object: &Map<String, Value>,
    key: &str,
    previous: Option<u64>,
) -> Result<u64, WireDecodeError> {
    object.get(key).map_or_else(
        || Ok(previous.unwrap_or(0)),
        |value| value.as_u64().ok_or(WireDecodeError::InvalidUsage),
    )
}
fn finish_reason(root: &Map<String, Value>) -> Result<Option<&str>, WireDecodeError> {
    let candidate = root
        .get("candidates")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_object)
        .ok_or(WireDecodeError::Malformed)?;
    Ok(candidate.get("finishReason").and_then(Value::as_str))
}
fn stop_reason(
    reason: &str,
) -> Result<(ProviderTerminalDisposition, ProviderFinishReason), WireDecodeError> {
    match reason {
        "STOP" => Ok((
            ProviderTerminalDisposition::Completed,
            ProviderFinishReason::Stop,
        )),
        "MAX_TOKENS" => Ok((
            ProviderTerminalDisposition::RemoteIncomplete,
            ProviderFinishReason::Length,
        )),
        "SAFETY" | "RECITATION" | "BLOCKLIST" | "PROHIBITED_CONTENT" | "SPII" | "IMAGE_SAFETY" => {
            Ok((
                ProviderTerminalDisposition::RemoteIncomplete,
                ProviderFinishReason::ContentFilter,
            ))
        }
        "MALFORMED_FUNCTION_CALL" => Err(WireDecodeError::UnsupportedContent),
        "OTHER" => Ok((
            ProviderTerminalDisposition::RemoteFailed,
            ProviderFinishReason::Error,
        )),
        _ => Err(WireDecodeError::Malformed),
    }
}
