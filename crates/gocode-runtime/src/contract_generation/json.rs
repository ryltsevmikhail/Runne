fn canonical_json(value: &Value) -> Result<Vec<u8>, serde_json::Error> {
    let mut bytes = serde_json::to_vec_pretty(&sorted_value(value))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn sorted_value(value: &Value) -> Value {
    match value {
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| (key.clone(), sorted_value(value)))
                .collect::<Map<_, _>>(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(sorted_value).collect()),
        scalar => scalar.clone(),
    }
}

fn string_schema(max_length: u64) -> Value {
    json!({"maxLength": max_length, "minLength": 1, "type": "string"})
}

fn uuid_v7_schema() -> Value {
    json!({"pattern": UUID_V7_PATTERN, "type": "string"})
}

fn nullable_uuid_v7_schema() -> Value {
    json!({"oneOf": [uuid_v7_schema(), {"type": "null"}]})
}

fn replay_session_id_schema() -> Value {
    json!({"pattern": LOWER_HEX_16_PATTERN, "type": "string"})
}

fn positive_integer_schema() -> Value {
    json!({"minimum": 1, "type": "integer"})
}

fn enum_schema(values: &[&str]) -> Value {
    json!({"enum": values, "type": "string"})
}

fn closed_object(properties: Value, required: &[&str]) -> Value {
    json!({
        "additionalProperties": false,
        "properties": properties,
        "required": required,
        "type": "object",
    })
}

fn payload_variant(event_type: &str, fields: &[(&str, Value)]) -> Value {
    let mut properties = Map::new();
    properties.insert(
        "type".to_owned(),
        json!({"const": event_type, "type": "string"}),
    );
    let mut required = vec!["type".to_owned()];
    for (name, schema) in fields {
        properties.insert((*name).to_owned(), schema.clone());
        required.push((*name).to_owned());
    }
    required.sort();
    json!({
        "additionalProperties": false,
        "properties": properties,
        "required": required,
        "type": "object",
    })
}
