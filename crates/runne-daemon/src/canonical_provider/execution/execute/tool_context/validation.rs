use super::*;
pub(super) fn inspect_plain_bytes(
    service: &DaemonCanonicalProviderService,
    bytes: &[u8],
) -> Result<(), CanonicalProviderExecutionError> {
    if !matches!(
        service.prohibited_content.inspect(
            runne_application::prohibited_content::CanonicalContentBoundary::CanonicalMutation,
            bytes,
        ),
        Ok(runne_application::prohibited_content::ContentDisposition::Allowed { .. })
    ) {
        return Err(CanonicalProviderExecutionError::PolicyDenied);
    }
    Ok(())
}

pub(super) fn validate_arguments_for_mode(
    bytes: &[u8],
    tool_name: &str,
    coding: bool,
) -> Result<(String, Option<Vec<u8>>), CanonicalProviderExecutionError> {
    if bytes.is_empty() || bytes.len() > 8 * 1024 {
        return Err(CanonicalProviderExecutionError::Uncertain);
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| CanonicalProviderExecutionError::Uncertain)?;
    if serde_json::to_vec(&value).map_err(|_| CanonicalProviderExecutionError::Uncertain)? != bytes
    {
        return Err(CanonicalProviderExecutionError::Uncertain);
    }
    if coding {
        let args = crate::safe_tool_helper::coding_arguments::parse(tool_name, &value)
            .map_err(|_| CanonicalProviderExecutionError::Uncertain)?;
        return Ok((
            String::from_utf8(bytes.to_vec())
                .map_err(|_| CanonicalProviderExecutionError::Uncertain)?,
            Some(args.content),
        ));
    }
    let object = value
        .as_object()
        .ok_or(CanonicalProviderExecutionError::Uncertain)?;
    let path = object
        .get("path")
        .and_then(serde_json::Value::as_str)
        .ok_or(CanonicalProviderExecutionError::Uncertain)?;
    if path.is_empty()
        || path.len() > 255
        || path == "."
        || path == ".."
        || path.contains('/')
        || path.contains('\\')
        || path.as_bytes().contains(&0)
    {
        return Err(CanonicalProviderExecutionError::Uncertain);
    }
    let create_content = match (tool_name, object.len()) {
        ("workspace.file.read", 1) => None,
        ("workspace.file.create_new", 2) => {
            let encoded = object
                .get("content_base64")
                .and_then(serde_json::Value::as_str)
                .ok_or(CanonicalProviderExecutionError::Uncertain)?;
            let content =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
                    .map_err(|_| CanonicalProviderExecutionError::Uncertain)?;
            if content.len() > 8 * 1024 {
                return Err(CanonicalProviderExecutionError::Uncertain);
            }
            Some(content)
        }
        _ => return Err(CanonicalProviderExecutionError::Uncertain),
    };
    Ok((
        String::from_utf8(bytes.to_vec())
            .map_err(|_| CanonicalProviderExecutionError::Uncertain)?,
        create_content,
    ))
}

#[cfg(test)]
pub(super) fn validate_arguments(
    bytes: &[u8],
    tool: &str,
) -> Result<(String, Option<Vec<u8>>), CanonicalProviderExecutionError> {
    validate_arguments_for_mode(bytes, tool, false)
}

pub(super) fn command_output_bytes(
    bytes: &[u8],
) -> Result<[Vec<u8>; 2], CanonicalProviderExecutionError> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| CanonicalProviderExecutionError::Uncertain)?;
    let decode = |field: &str| -> Result<Vec<u8>, CanonicalProviderExecutionError> {
        let encoded = value
            .get(field)
            .and_then(serde_json::Value::as_str)
            .ok_or(CanonicalProviderExecutionError::Uncertain)?;
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
            .map_err(|_| CanonicalProviderExecutionError::Uncertain)?;
        if bytes.len() > 2048 {
            return Err(CanonicalProviderExecutionError::Uncertain);
        }
        Ok(bytes)
    };
    Ok([decode("stdout_base64")?, decode("stderr_base64")?])
}
