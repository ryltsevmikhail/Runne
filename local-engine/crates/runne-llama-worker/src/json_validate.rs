//! Final-output revalidation (Plan Task 19): before `finish`, the
//! complete structured output is parsed and validated against the
//! schema subset. Invalid output fails the attempt typed
//! (`StructuredOutputInvalid` semantics) — partial output is never
//! accepted, and the worker emits no `finish` item for it.

use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputRejected;

/// Validates the complete output text against the schema subset.
pub fn validate_output(schema: &Value, output: &str) -> Result<(), OutputRejected> {
    let value: Value = serde_json::from_str(output).map_err(|_| OutputRejected)?;
    check(&value, schema, 0)
}

fn check(v: &Value, schema: &Value, depth: usize) -> Result<(), OutputRejected> {
    if depth > 16 {
        return Err(OutputRejected);
    }
    let Value::Object(m) = schema else {
        return Err(OutputRejected);
    };
    if let Some(Value::Array(values)) = m.get("enum") {
        return if values.contains(v) {
            Ok(())
        } else {
            Err(OutputRejected)
        };
    }
    let ty = match m.get("type") {
        Some(Value::String(t)) => t.as_str(),
        _ => return Err(OutputRejected),
    };
    match ty {
        "string" => matches!(v, Value::String(_)),
        "integer" => matches!(v, Value::Number(n) if n.is_u64() || n.is_i64()),
        "number" => matches!(v, Value::Number(_)),
        "boolean" => matches!(v, Value::Bool(_)),
        "null" => matches!(v, Value::Null),
        "array" => {
            let Value::Array(items) = v else {
                return Err(OutputRejected);
            };
            let item_schema = m.get("items").ok_or(OutputRejected)?;
            for item in items {
                check(item, item_schema, depth + 1)?;
            }
            true
        }
        "object" => {
            let Value::Object(map) = v else {
                return Err(OutputRejected);
            };
            let props = match m.get("properties") {
                Some(Value::Object(p)) => p,
                _ => return Err(OutputRejected),
            };
            let required: Vec<&str> = match m.get("required") {
                Some(Value::Array(items)) => items.iter().filter_map(|i| i.as_str()).collect(),
                _ => Vec::new(),
            };
            // Closed objects: no additional keys beyond declared ones.
            for key in map.keys() {
                if !props.contains_key(key) {
                    return Err(OutputRejected);
                }
            }
            for key in required {
                map.get(key).ok_or(OutputRejected)?;
            }
            for (key, val) in map {
                if let Some(sub) = props.get(key) {
                    check(val, sub, depth + 1)?;
                }
            }
            true
        }
        _ => false,
    }
    .then_some(())
    .ok_or(OutputRejected)
}
