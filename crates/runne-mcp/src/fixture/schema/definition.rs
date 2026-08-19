use std::collections::BTreeSet;

use serde_json::Value;

use super::{validate_value, value::normalized_forbidden};
use crate::{FixtureLimits, FixtureMcpFailure};

const SCHEMA_KEYS: &[&str] = &[
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "minLength",
    "maxLength",
    "minimum",
    "maximum",
    "enum",
];

pub(crate) fn validate_schema(schema: &Value) -> Result<(), FixtureMcpFailure> {
    validate_value(schema, &FixtureLimits::default())?;
    let object = schema
        .as_object()
        .ok_or(FixtureMcpFailure::ToolDefinitionInvalid)?;
    if object
        .keys()
        .any(|key| !SCHEMA_KEYS.contains(&key.as_str()))
    {
        return Err(FixtureMcpFailure::ToolDefinitionInvalid);
    }
    let kind = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or(FixtureMcpFailure::ToolDefinitionInvalid)?;
    if !matches!(
        kind,
        "object" | "array" | "string" | "integer" | "boolean" | "null"
    ) || object.get("enum").is_some_and(|value| {
        value
            .as_array()
            .is_none_or(|items| items.is_empty() || items.len() > 64)
    }) || !enum_matches_kind(object, kind)
    {
        return Err(FixtureMcpFailure::ToolDefinitionInvalid);
    }
    match kind {
        "object" => validate_object_schema(object),
        "array" => validate_array_schema(object),
        "string" | "integer" => validate_scalar_schema(object),
        "boolean" | "null"
            if object
                .keys()
                .all(|key| matches!(key.as_str(), "type" | "enum")) =>
        {
            Ok(())
        }
        _ => Err(FixtureMcpFailure::ToolDefinitionInvalid),
    }
}

fn validate_object_schema(
    object: &serde_json::Map<String, Value>,
) -> Result<(), FixtureMcpFailure> {
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "type" | "properties" | "required" | "additionalProperties" | "enum"
        )
    }) || object.get("additionalProperties") != Some(&Value::Bool(false))
    {
        return Err(FixtureMcpFailure::ToolDefinitionInvalid);
    }
    let empty = serde_json::Map::new();
    let properties = match object.get("properties") {
        Some(value) => value
            .as_object()
            .ok_or(FixtureMcpFailure::ToolDefinitionInvalid)?,
        None => &empty,
    };
    if properties.len() > 64 || properties.keys().any(|key| normalized_forbidden(key)) {
        return Err(FixtureMcpFailure::ToolDefinitionInvalid);
    }
    for schema in properties.values() {
        validate_schema(schema)?;
    }
    let no_required = Vec::new();
    let required = match object.get("required") {
        Some(value) => value
            .as_array()
            .ok_or(FixtureMcpFailure::ToolDefinitionInvalid)?,
        None => &no_required,
    };
    let required_names = required
        .iter()
        .map(Value::as_str)
        .collect::<Option<BTreeSet<_>>>();
    if required.len() > properties.len()
        || required.iter().any(|name| {
            name.as_str()
                .is_none_or(|name| !properties.contains_key(name))
        })
        || required_names.is_none_or(|names| names.len() != required.len())
    {
        return Err(FixtureMcpFailure::ToolDefinitionInvalid);
    }
    Ok(())
}

fn validate_array_schema(object: &serde_json::Map<String, Value>) -> Result<(), FixtureMcpFailure> {
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "type" | "items" | "enum"))
    {
        return Err(FixtureMcpFailure::ToolDefinitionInvalid);
    }
    object
        .get("items")
        .ok_or(FixtureMcpFailure::ToolDefinitionInvalid)
        .and_then(validate_schema)
}

fn validate_scalar_schema(
    object: &serde_json::Map<String, Value>,
) -> Result<(), FixtureMcpFailure> {
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "type" | "minLength" | "maxLength" | "minimum" | "maximum" | "enum"
        )
    }) || object
        .get("minLength")
        .is_some_and(|v| v.as_u64().is_none())
        || object
            .get("maxLength")
            .is_some_and(|v| v.as_u64().is_none())
        || object.get("minimum").is_some_and(|v| v.as_i64().is_none())
        || object.get("maximum").is_some_and(|v| v.as_i64().is_none())
        || object.get("minLength").and_then(Value::as_u64)
            > object.get("maxLength").and_then(Value::as_u64)
        || object.get("minimum").and_then(Value::as_i64)
            > object.get("maximum").and_then(Value::as_i64)
    {
        return Err(FixtureMcpFailure::ToolDefinitionInvalid);
    }
    Ok(())
}

fn enum_matches_kind(object: &serde_json::Map<String, Value>, kind: &str) -> bool {
    object
        .get("enum")
        .and_then(Value::as_array)
        .is_none_or(|items| {
            items.iter().all(|value| match kind {
                "object" => value.is_object(),
                "array" => value.is_array(),
                "string" => value.is_string(),
                "integer" => value.as_i64().is_some(),
                "boolean" => value.is_boolean(),
                "null" => value.is_null(),
                _ => false,
            })
        })
}
