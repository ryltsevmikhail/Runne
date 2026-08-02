fn validate_session_id(session_id: &str) -> Result<(), crate::error::SessionV1Error> {
    if session_id.starts_with("ses")
        && session_id.len() <= 256
        && !session_id
            .bytes()
            .any(|byte| byte == 0 || byte < 0x20 || byte == 0x7f)
    {
        Ok(())
    } else {
        Err(crate::error::SessionV1Error::InvalidSessionId)
    }
}

fn parse_prompt(
    session_id: &str,
    input: serde_json::Value,
) -> Result<CanonicalPrompt, crate::error::SessionV1Error> {
    validate_session_id(session_id)?;
    let object = input
        .as_object()
        .ok_or(crate::error::SessionV1Error::InvalidRequest {
            detail: "prompt body must be an object",
        })?;
    for field in [
        "model", "agent", "noReply", "tools", "format", "system", "variant",
    ] {
        if object.contains_key(field) {
            return Err(crate::error::SessionV1Error::UnsupportedField { field });
        }
    }
    if object
        .keys()
        .any(|field| field != "messageID" && field != "parts")
    {
        return Err(crate::error::SessionV1Error::InvalidRequest {
            detail: "unknown prompt field",
        });
    }
    let message_id = match object.get("messageID") {
        Some(serde_json::Value::String(value))
            if value.starts_with("msg")
                && value.len() <= 256
                && !value
                    .bytes()
                    .any(|byte| byte == 0 || byte < 0x20 || byte == 0x7f) =>
        {
            Some(value.clone())
        }
        Some(_) => {
            return Err(crate::error::SessionV1Error::InvalidRequest {
                detail: "invalid messageID",
            });
        }
        None => None,
    };
    let parts = object
        .get("parts")
        .and_then(serde_json::Value::as_array)
        .ok_or(crate::error::SessionV1Error::InvalidRequest {
            detail: "parts must be an array",
        })?;
    if parts.len() > MAX_PROMPT_PARTS {
        return Err(crate::error::SessionV1Error::InvalidRequest {
            detail: "too many prompt parts",
        });
    }
    let mut text_parts = Vec::with_capacity(parts.len());
    let mut text_bytes = 0usize;
    for (index, part) in parts.iter().enumerate() {
        let Some(part) = part.as_object() else {
            return Err(crate::error::SessionV1Error::UnsupportedPart { index });
        };
        if part.len() != 2 || part.get("type").and_then(serde_json::Value::as_str) != Some("text") {
            return Err(crate::error::SessionV1Error::UnsupportedPart { index });
        }
        let Some(text) = part.get("text").and_then(serde_json::Value::as_str) else {
            return Err(crate::error::SessionV1Error::UnsupportedPart { index });
        };
        text_bytes = text_bytes.checked_add(text.len()).ok_or(
            crate::error::SessionV1Error::InvalidRequest {
                detail: "prompt text exceeds its bound",
            },
        )?;
        if text_bytes > MAX_PROMPT_TEXT_BYTES {
            return Err(crate::error::SessionV1Error::InvalidRequest {
                detail: "prompt text exceeds its bound",
            });
        }
        text_parts.push(text.to_owned());
    }
    Ok(CanonicalPrompt {
        session_id: session_id.to_owned(),
        message_id,
        text_parts,
    })
}

fn valid_prompt_response(session_id: &str, response: &serde_json::Value) -> bool {
    let Some(object) = response.as_object() else {
        return false;
    };
    if object.keys().any(|key| key != "info" && key != "parts") {
        return false;
    }
    let Some(info) = object.get("info").and_then(serde_json::Value::as_object) else {
        return false;
    };
    info.get("sessionID").and_then(serde_json::Value::as_str) == Some(session_id)
        && info.get("role").and_then(serde_json::Value::as_str) == Some("assistant")
        && object
            .get("parts")
            .and_then(serde_json::Value::as_array)
            .is_some()
}
