use serde_json::Value;

use super::super::model::FixtureLimits;
use crate::FixtureMcpFailure;

const FORBIDDEN_KEYS: &[&str] = &[
    "authorization",
    "credential",
    "api_key",
    "access_token",
    "refresh_token",
    "secret",
    "private_key",
    "cookie",
    "session_secret",
    "environment",
    "env",
    "path",
    "provider",
    "prompt",
    "output",
    "error",
];

pub(crate) fn validate_value(
    value: &Value,
    limits: &FixtureLimits,
) -> Result<(), FixtureMcpFailure> {
    if serde_json::to_vec(value)
        .map_err(|_| FixtureMcpFailure::RequestTooLarge)?
        .len()
        > limits.max_bytes
    {
        return Err(FixtureMcpFailure::RequestTooLarge);
    }
    validate_value_inner(value, limits, 0)
}

fn validate_value_inner(
    value: &Value,
    limits: &FixtureLimits,
    depth: usize,
) -> Result<(), FixtureMcpFailure> {
    if depth > limits.max_depth {
        return Err(FixtureMcpFailure::RequestTooLarge);
    }
    match value {
        Value::String(text) if text.len() > limits.max_string_bytes => {
            Err(FixtureMcpFailure::RequestTooLarge)
        }
        Value::Array(items) => {
            if items.len() > limits.max_items {
                return Err(FixtureMcpFailure::RequestTooLarge);
            }
            for item in items {
                validate_value_inner(item, limits, depth + 1)?;
            }
            Ok(())
        }
        Value::Object(items) => {
            if items.len() > limits.max_items {
                return Err(FixtureMcpFailure::RequestTooLarge);
            }
            for (key, item) in items {
                if key.len() > limits.max_string_bytes {
                    return Err(FixtureMcpFailure::RequestTooLarge);
                }
                validate_value_inner(item, limits, depth + 1)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub(crate) fn validate_instance(schema: &Value, value: &Value) -> Result<(), FixtureMcpFailure> {
    let object = schema
        .as_object()
        .ok_or(FixtureMcpFailure::InputSchemaMismatch)?;
    let kind = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or(FixtureMcpFailure::InputSchemaMismatch)?;
    let valid = match kind {
        "object" => validate_object_instance(object, value),
        "array" => value.as_array().is_some_and(|items| {
            object.get("items").is_some_and(|schema| {
                items
                    .iter()
                    .all(|item| validate_instance(schema, item).is_ok())
            })
        }),
        "string" => value.as_str().is_some(),
        "integer" => value.as_i64().is_some(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        _ => false,
    } && constraints_match(object, value);
    if valid {
        Ok(())
    } else {
        Err(FixtureMcpFailure::InputSchemaMismatch)
    }
}

fn validate_object_instance(schema: &serde_json::Map<String, Value>, value: &Value) -> bool {
    let Some(value) = value.as_object() else {
        return false;
    };
    let empty = serde_json::Map::new();
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let no_required = Vec::new();
    let required = schema
        .get("required")
        .and_then(Value::as_array)
        .unwrap_or(&no_required);
    required
        .iter()
        .all(|key| key.as_str().is_some_and(|key| value.contains_key(key)))
        && value.keys().all(|key| properties.contains_key(key))
        && value
            .iter()
            .all(|(key, item)| validate_instance(&properties[key], item).is_ok())
}

fn constraints_match(schema: &serde_json::Map<String, Value>, value: &Value) -> bool {
    if schema
        .get("enum")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.contains(value))
    {
        return false;
    }
    if let Some(text) = value.as_str()
        && (schema
            .get("minLength")
            .and_then(Value::as_u64)
            .is_some_and(|n| text.chars().count() < n as usize)
            || schema
                .get("maxLength")
                .and_then(Value::as_u64)
                .is_some_and(|n| text.chars().count() > n as usize))
    {
        return false;
    }
    if let Some(number) = value.as_i64()
        && (schema
            .get("minimum")
            .and_then(Value::as_i64)
            .is_some_and(|n| number < n)
            || schema
                .get("maximum")
                .and_then(Value::as_i64)
                .is_some_and(|n| number > n))
    {
        return false;
    }
    true
}

pub(crate) fn reject_secret_material(value: &Value) -> Result<(), FixtureMcpFailure> {
    match value {
        Value::String(text)
            if normalized_forbidden(text) || text.contains('/') || text.contains('\\') =>
        {
            return Err(FixtureMcpFailure::SecretMaterialRejected);
        }
        Value::Array(items) => {
            for item in items {
                reject_secret_material(item)?;
            }
        }
        Value::Object(items) => {
            for (key, item) in items {
                if normalized_forbidden(key) {
                    return Err(FixtureMcpFailure::SecretMaterialRejected);
                }
                reject_secret_material(item)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn normalized_forbidden(value: &str) -> bool {
    let normalized: String = value
        .bytes()
        .filter_map(|byte| {
            byte.is_ascii_alphanumeric()
                .then_some((byte as char).to_ascii_lowercase())
        })
        .collect();
    FORBIDDEN_KEYS
        .iter()
        .any(|key| normalized.contains(&key.replace('_', "")))
}
