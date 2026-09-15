use serde_json::Value;

use super::RadiusConfigError;

pub(super) fn reject_unknown_keys(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
) -> Result<(), RadiusConfigError> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        Err(RadiusConfigError::Malformed)
    } else {
        Ok(())
    }
}

pub(super) fn reject_credential_keys(
    object: &serde_json::Map<String, Value>,
) -> Result<(), RadiusConfigError> {
    if object.keys().any(|key| {
        let key = key.to_ascii_lowercase().replace(['_', '-'], "");
        key.contains("apikey")
            || key.contains("authorization")
            || (key.ends_with("token") && key != "maxtokens")
            || key.contains("credential")
    }) {
        Err(RadiusConfigError::Malformed)
    } else {
        Ok(())
    }
}

pub(super) fn bounded_string(value: Option<&Value>) -> Result<String, RadiusConfigError> {
    let string = value
        .and_then(Value::as_str)
        .ok_or(RadiusConfigError::InvalidModel)?;
    if string.is_empty() || string.len() > 512 || string.chars().any(char::is_control) {
        return Err(RadiusConfigError::InvalidModel);
    }
    Ok(string.to_owned())
}

pub(super) fn bounded_u64(
    value: Option<&Value>,
    allow_zero: bool,
) -> Result<u64, RadiusConfigError> {
    let number = value
        .and_then(Value::as_u64)
        .ok_or(RadiusConfigError::InvalidModel)?;
    if (!allow_zero && number == 0) || number > 1_000_000_000 {
        return Err(RadiusConfigError::InvalidModel);
    }
    Ok(number)
}
