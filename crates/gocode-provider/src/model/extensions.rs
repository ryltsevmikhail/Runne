fn validate_extension(value: &Value, depth: usize) -> Result<(), ProviderCallError> {
    if depth > MAX_EXTENSION_DEPTH {
        return Err(ProviderCallError::ExtensionTooDeep);
    }
    if depth == 0 {
        let actual = serde_json::to_vec(value)
            .map_err(|_| ProviderCallError::ExtensionTooLarge {
                max: MAX_EXTENSION_BYTES,
                actual: usize::MAX,
            })?
            .len();
        if actual > MAX_EXTENSION_BYTES {
            return Err(ProviderCallError::ExtensionTooLarge {
                max: MAX_EXTENSION_BYTES,
                actual,
            });
        }
    }
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let normalized = normalize_extension_key(key);
                if normalized.contains("secret")
                    || normalized.contains("password")
                    || normalized.contains("authorization")
                    || normalized.contains("api_key")
                    || normalized == "token"
                    || normalized.ends_with("_token")
                {
                    return Err(ProviderCallError::CredentialField(key.clone()));
                }
                validate_extension(child, depth + 1)?;
            }
        }
        Value::Array(values) => {
            for child in values {
                validate_extension(child, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn normalize_extension_key(key: &str) -> String {
    let characters = key.chars().collect::<Vec<_>>();
    let mut normalized = String::with_capacity(key.len());

    for (index, character) in characters.iter().copied().enumerate() {
        if character.is_ascii_alphanumeric() {
            if character.is_ascii_uppercase() {
                let previous = index
                    .checked_sub(1)
                    .and_then(|previous| characters.get(previous));
                let next = characters.get(index + 1);
                let separates_word = previous.is_some_and(|previous| {
                    previous.is_ascii_lowercase()
                        || previous.is_ascii_digit()
                        || (previous.is_ascii_uppercase()
                            && next.is_some_and(|next| next.is_ascii_lowercase()))
                });
                if separates_word && !normalized.ends_with('_') {
                    normalized.push('_');
                }
            }
            normalized.push(character.to_ascii_lowercase());
        } else if !normalized.is_empty() && !normalized.ends_with('_') {
            normalized.push('_');
        }
    }

    normalized.trim_matches('_').to_owned()
}

fn normalize_required_capabilities(
    mut required_capabilities: Vec<ProviderCapability>,
) -> Result<Vec<ProviderCapability>, ProviderCallError> {
    if required_capabilities.len() > MAX_REQUIRED_CAPABILITIES {
        return Err(ProviderCallError::TooManyRequiredCapabilities {
            max: MAX_REQUIRED_CAPABILITIES,
            actual: required_capabilities.len(),
        });
    }
    required_capabilities.sort_unstable();
    required_capabilities.dedup();
    Ok(required_capabilities)
}
