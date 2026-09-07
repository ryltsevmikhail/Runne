//! Structured-output schema subset v1 (REQ-PROV-123): the closed
//! keyword set the engine accepts (`type`, `properties`, `required`,
//! `items`, `enum`, `additionalProperties: false`, `description`).
//! Recursion-bearing and alternation keywords (`$ref`, `definitions`,
//! `oneOf`, `anyOf`, `allOf`, `not`, `if`, `patternProperties`, …)
//! are OUT of subset and reject typed. Bounds: ≤ 12 KiB canonical,
//! depth ≤ 16.

use serde_json::Value;

pub const MAX_SCHEMA_BYTES: usize = 12 * 1024;
pub const MAX_SCHEMA_DEPTH: usize = 16;

pub const SUPPORTED_TYPES: [&str; 7] = [
    "object", "array", "string", "integer", "number", "boolean", "null",
];

const SUPPORTED_KEYWORDS: [&str; 7] = [
    "type",
    "properties",
    "required",
    "items",
    "enum",
    "additionalProperties",
    "description",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaError {
    /// Canonical schema exceeds the 12 KiB bound.
    TooLarge,
    /// Nesting deeper than the bound (also rejects recursion via
    /// depth exhaustion).
    TooDeep,
    /// A keyword outside the v1 subset.
    UnsupportedKeyword(String),
    /// Structurally invalid per the subset (bad type name, required
    /// not strings, enum empty, …).
    Malformed,
}

fn unsupported(k: &str) -> SchemaError {
    SchemaError::UnsupportedKeyword(k.to_string())
}

/// Validates one subschema node against the v1 subset.
pub fn validate_schema_subset(canonical_schema: &str) -> Result<(), SchemaError> {
    if canonical_schema.len() > MAX_SCHEMA_BYTES {
        return Err(SchemaError::TooLarge);
    }
    let value: Value =
        serde_json::from_str(canonical_schema).map_err(|_| SchemaError::Malformed)?;
    walk(&value, 0)
}

fn walk(v: &Value, depth: usize) -> Result<(), SchemaError> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(SchemaError::TooDeep);
    }
    let Value::Object(map) = v else {
        return Err(SchemaError::Malformed);
    };
    for key in map.keys() {
        if !SUPPORTED_KEYWORDS.contains(&key.as_str()) {
            return Err(unsupported(key));
        }
    }
    if let Some(Value::String(ty)) = map.get("type") {
        if !SUPPORTED_TYPES.contains(&ty.as_str()) {
            return Err(SchemaError::Malformed);
        }
    } else if map.contains_key("type") {
        return Err(SchemaError::Malformed);
    }
    if let Some(Value::Object(props)) = map.get("properties") {
        for (name, sub) in props {
            if name.is_empty() {
                return Err(SchemaError::Malformed);
            }
            walk(sub, depth + 1)?;
        }
    }
    if let Some(req) = map.get("required") {
        let Value::Array(items) = req else {
            return Err(SchemaError::Malformed);
        };
        if items.iter().any(|i| !matches!(i, Value::String(_))) {
            return Err(SchemaError::Malformed);
        }
    }
    if let Some(items) = map.get("items") {
        walk(items, depth + 1)?;
    }
    if let Some(e) = map.get("enum") {
        let Value::Array(items) = e else {
            return Err(SchemaError::Malformed);
        };
        if items.is_empty() {
            return Err(SchemaError::Malformed);
        }
    }
    if let Some(ap) = map.get("additionalProperties") {
        // Only the closed-object form is in subset.
        if !matches!(ap, Value::Bool(false)) {
            return Err(SchemaError::Malformed);
        }
    }
    if let Some(Value::String(d)) = map.get("description")
        && d.len() > MAX_SCHEMA_BYTES
    {
        return Err(SchemaError::TooLarge);
    }
    Ok(())
}
