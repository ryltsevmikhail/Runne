fn checked_text(value: String) -> Result<String, FixtureMcpFailure> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES || !value.bytes().all(|byte| byte.is_ascii_graphic()) { return Err(FixtureMcpFailure::ToolDefinitionInvalid); }
    Ok(value)
}

fn checked_tool_name(value: String) -> Result<String, FixtureMcpFailure> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES || !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)) { return Err(FixtureMcpFailure::ToolDefinitionInvalid); }
    Ok(value)
}

fn checked_description(value: String) -> Result<String, FixtureMcpFailure> {
    if value.is_empty() || value.len() > MAX_TEXT_BYTES || !value.bytes().all(|byte| byte.is_ascii() && !byte.is_ascii_control()) { return Err(FixtureMcpFailure::ToolDefinitionInvalid); }
    Ok(value)
}

pub(crate) fn digest(values: &[&[u8]]) -> [u8; 32] {
    digest_domain(b"RUNNE_MCP_FIXTURE_V1\0", values)
}

pub(crate) fn digest_domain(domain: &[u8], values: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for value in values { hasher.update((value.len() as u64).to_be_bytes()); hasher.update(value); }
    hasher.finalize().into()
}
